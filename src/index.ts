import { DurableObject } from "cloudflare:workers";

const ADMIN_SECRET_FALLBACK = "5821";
const TTL_MS = 24 * 60 * 60 * 1000;

type AuthStatus = "pending" | "approved" | "blocked" | "expired";

type AuthRecord = {
	status: AuthStatus;
	name: string;
	contact: string;
	appliedAt: number | null;
	approvedAt: number | null;
};

type ApplyResult =
	| { status: "applied"; record: AuthRecord }
	| { status: "already_pending"; record: AuthRecord }
	| { status: "already_approved"; record: AuthRecord }
	| { status: "blocked"; record: AuthRecord }
	| { status: "error"; error: string };

type ActionResult =
	| { success: true; record: AuthRecord }
	| { success: false; error: string };

export class MyDurableObject extends DurableObject<Env> {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
	}

	private normalizeRecord(record: unknown): AuthRecord | null {
		if (!record || typeof record !== "object") return null;

		const r = record as Partial<AuthRecord>;

		return {
			status: (r.status as AuthStatus) || "pending",
			name: String(r.name || "").trim().slice(0, 30),
			contact: String(r.contact || "").trim().slice(0, 50),
			appliedAt: Number(r.appliedAt || 0) || null,
			approvedAt: Number(r.approvedAt || 0) || null,
		};
	}

	private async getStoredRecord(): Promise<AuthRecord | null> {
		const record = await this.ctx.storage.get<AuthRecord>("record");
		return this.normalizeRecord(record);
	}

	private async putStoredRecord(record: AuthRecord): Promise<void> {
		const normalized = this.normalizeRecord(record);
		if (!normalized) return;
		await this.ctx.storage.put("record", normalized);
	}

	private async markExpiredIfNeeded(record: AuthRecord | null): Promise<AuthRecord | null> {
		const normalized = this.normalizeRecord(record);
		if (!normalized) return null;

		if (
			normalized.status === "approved" &&
			normalized.approvedAt &&
			Date.now() - normalized.approvedAt > TTL_MS
		) {
			normalized.status = "expired";
			await this.putStoredRecord(normalized);
		}

		return normalized;
	}

	async getRecord(): Promise<AuthRecord | null> {
		return this.markExpiredIfNeeded(await this.getStoredRecord());
	}

	async apply(name: string, contact: string): Promise<ApplyResult> {
		const safeName = String(name || "").trim().slice(0, 30);
		const safeContact = String(contact || "").trim().slice(0, 50);

		if (!safeName || !safeContact) {
			return { status: "error", error: "이름과 연락처를 입력해주세요." };
		}

		const existing = await this.markExpiredIfNeeded(await this.getStoredRecord());

		if (existing) {
			if (existing.status === "pending") {
				return { status: "already_pending", record: existing };
			}

			if (existing.status === "approved") {
				return { status: "already_approved", record: existing };
			}

			if (existing.status === "blocked") {
				return { status: "blocked", record: existing };
			}
		}

		const record: AuthRecord = {
			status: "pending",
			name: safeName,
			contact: safeContact,
			appliedAt: Date.now(),
			approvedAt: null,
		};

		await this.putStoredRecord(record);
		return { status: "applied", record };
	}

	async approve(): Promise<ActionResult> {
		const existing = await this.markExpiredIfNeeded(await this.getStoredRecord());

		const updated: AuthRecord = {
			status: "approved",
			name: existing?.name || "",
			contact: existing?.contact || "",
			appliedAt: existing?.appliedAt || Date.now(),
			approvedAt: Date.now(),
		};

		await this.putStoredRecord(updated);
		return { success: true, record: updated };
	}

	async extend(): Promise<ActionResult> {
		const existing = await this.markExpiredIfNeeded(await this.getStoredRecord());
		if (!existing) {
			return { success: false, error: "존재하지 않는 IP" };
		}

		const updated: AuthRecord = {
			...existing,
			status: "approved",
			approvedAt: Date.now(),
		};

		await this.putStoredRecord(updated);
		return { success: true, record: updated };
	}

	async block(): Promise<ActionResult> {
		const existing = await this.markExpiredIfNeeded(await this.getStoredRecord());

		const updated: AuthRecord = {
			status: "blocked",
			name: existing?.name || "",
			contact: existing?.contact || "",
			appliedAt: existing?.appliedAt || Date.now(),
			approvedAt: existing?.approvedAt || null,
		};

		await this.putStoredRecord(updated);
		return { success: true, record: updated };
	}

	async deleteRecord(): Promise<{ success: true }> {
		await this.ctx.storage.delete("record");
		return { success: true };
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const corsHeaders = {
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret",
		};

		const json = (data: unknown, status = 200) =>
			new Response(JSON.stringify(data), {
				status,
				headers: {
					...corsHeaders,
					"Content-Type": "application/json; charset=utf-8",
					"Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
					Pragma: "no-cache",
					Expires: "0",
				},
			});

		try {
			const url = new URL(request.url);
			const path = url.pathname;
			const method = request.method;
			const adminSecret = env.ADMIN_SECRET || ADMIN_SECRET_FALLBACK;

			if (method === "OPTIONS") {
				return new Response(null, { headers: corsHeaders });
			}

			const isAdmin = () =>
				request.headers.get("X-Admin-Secret") === adminSecret ||
				url.searchParams.get("secret") === adminSecret;

			const ensureKV = () => {
				if (!env.AUTH_KV) {
					throw new Error("AUTH_KV binding is missing");
				}
			};

			const getClientIp = () => {
				const ip = request.headers.get("CF-Connecting-IP");
				return ip ? ip.trim() : null;
			};

			const getStubByIp = (ip: string) => {
				const id = env.MY_DURABLE_OBJECT.idFromName(ip);
				return env.MY_DURABLE_OBJECT.get(id);
			};

			const writeIndex = async (ip: string, record: AuthRecord) => {
				ensureKV();
				await env.AUTH_KV.put(ip, JSON.stringify(record));
			};

			const readIndex = async (ip: string): Promise<AuthRecord | null> => {
				ensureKV();
				const raw = await env.AUTH_KV.get(ip);
				if (!raw) return null;

				try {
					return JSON.parse(raw) as AuthRecord;
				} catch (err) {
					console.error("Invalid KV JSON for IP:", ip, raw);
					return null;
				}
			};

			const deleteIndex = async (ip: string) => {
				ensureKV();
				await env.AUTH_KV.delete(ip);
			};

			const normalizeRecord = (record: unknown): AuthRecord | null => {
				if (!record || typeof record !== "object") return null;
				const r = record as Partial<AuthRecord>;
				return {
					status: (r.status as AuthStatus) || "pending",
					name: String(r.name || "").slice(0, 30),
					contact: String(r.contact || "").slice(0, 50),
					appliedAt: Number(r.appliedAt || 0) || null,
					approvedAt: Number(r.approvedAt || 0) || null,
				};
			};

			const withExpirationIndex = async (ip: string, record: AuthRecord | null) => {
				const normalized = normalizeRecord(record);
				if (!normalized) return null;

				if (
					normalized.status === "approved" &&
					normalized.approvedAt &&
					Date.now() - normalized.approvedAt > TTL_MS
				) {
					normalized.status = "expired";
					await writeIndex(ip, normalized);
				}

				return normalized;
			};

			// [유저] GET /check
			if (path === "/check" && method === "GET") {
				const ip = getClientIp();
				if (!ip) {
					return json({ error: "IP 확인 불가" }, 400);
				}

				const stub = getStubByIp(ip);
				const record = await stub.getRecord();

				if (!record) return json({ status: "unregistered" });
				if (record.status === "blocked") return json({ status: "blocked" });

				if (record.status === "approved") {
					const remainMs = Math.max(0, TTL_MS - (Date.now() - (record.approvedAt || 0)));
					return json({ status: "approved", remainMs });
				}

				return json({ status: record.status });
			}

			// [유저] POST /apply
			if (path === "/apply" && method === "POST") {
				const ip = getClientIp();
				if (!ip) {
					return json({ error: "IP 확인 불가" }, 400);
				}

				const body = (await request.json().catch(() => ({}))) as {
					name?: string;
					contact?: string;
				};

				const stub = getStubByIp(ip);
				const result = await stub.apply(body.name || "", body.contact || "");

				if ("record" in result && result.record) {
					await writeIndex(ip, result.record);
				}

				return json(result, result.status === "error" ? 400 : 200);
			}

			// [관리자] GET /admin/list
			if (path === "/admin/list" && method === "GET") {
				if (!isAdmin()) return json({ error: "Unauthorized" }, 401);

				ensureKV();

				const result: Array<AuthRecord & { ip: string }> = [];
				let cursor: string | undefined = undefined;

				do {
					const page = await env.AUTH_KV.list({ cursor });
					cursor = page.list_complete ? undefined : page.cursor;

					for (const key of page.keys) {
						const record = await withExpirationIndex(key.name, await readIndex(key.name));
						if (!record) continue;
						result.push({ ip: key.name, ...record });
					}
				} while (cursor);

				result.sort((a, b) => {
					if (a.status === "pending" && b.status !== "pending") return -1;
					if (b.status === "pending" && a.status !== "pending") return 1;
					return (b.appliedAt || 0) - (a.appliedAt || 0);
				});

				return json(result);
			}

			// [관리자] POST /admin/approve /block /delete /extend
			if (path.startsWith("/admin/") && method === "POST") {
				if (!isAdmin()) return json({ error: "Unauthorized" }, 401);

				const body = (await request.json().catch(() => ({}))) as { ip?: string };
				const ip = String(body?.ip || "").trim();

				if (!ip) {
					return json({ error: "IP 없음" }, 400);
				}

				const action = path.replace("/admin/", "");
				const stub = getStubByIp(ip);

				if (action === "approve") {
					const result = await stub.approve();
					if (result.success) {
						await writeIndex(ip, result.record);
						return json({ success: true, ip, status: "approved" });
					}
					return json(result, 400);
				}

				if (action === "extend") {
					const result = await stub.extend();
					if (result.success) {
						await writeIndex(ip, result.record);
						return json({
							success: true,
							ip,
							status: "approved",
							note: "24시간 연장됨",
						});
					}
					return json({ error: result.error }, 404);
				}

				if (action === "block") {
					const result = await stub.block();
					if (result.success) {
						await writeIndex(ip, result.record);
						return json({ success: true, ip, status: "blocked" });
					}
					return json(result, 400);
				}

				if (action === "delete") {
					await stub.deleteRecord();
					await deleteIndex(ip);
					return json({ success: true, ip, deleted: true });
				}

				return json({ error: "알 수 없는 액션" }, 400);
			}

			// [관리자] GET /admin/ui
			if (path === "/admin/ui" && method === "GET") {
				const querySecret = url.searchParams.get("secret");
				if (querySecret !== adminSecret) {
					return new Response("Unauthorized", { status: 401 });
				}

				return new Response(ADMIN_HTML, {
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
			}

			// DO 연결 테스트용
			if (path === "/do-test" && method === "GET") {
				const ip = getClientIp() || "127.0.0.1";
				const stub = getStubByIp(ip);
				const record = await stub.getRecord();
				return json({ ok: true, ip, record });
			}

			return json({ error: "Not Found" }, 404);
		} catch (err) {
			console.error("Worker error:", err);

			return new Response(
				JSON.stringify({
					error: "Internal Server Error",
					message: err instanceof Error ? err.message : "Unknown error",
				}),
				{
					status: 500,
					headers: {
						...corsHeaders,
						"Content-Type": "application/json; charset=utf-8",
					},
				},
			);
		}
	},
} satisfies ExportedHandler<Env>;

// ── 관리자 웹 UI ──────────────────────────────────────────
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Strike Auth 관리자</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;padding:24px}
  h1{font-size:20px;color:#58a6ff;margin-bottom:20px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#161b22;padding:10px 12px;text-align:left;border-bottom:1px solid #30363d;color:#8b949e;font-weight:600}
  td{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:middle}
  tr:hover td{background:#161b22}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
  .badge-pending{background:#bb8009;color:#fff}
  .badge-approved{background:#238636;color:#fff}
  .badge-expired{background:#6e7681;color:#fff}
  .badge-blocked{background:#da3633;color:#fff}
  .btn-sm{border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600}
  .btn-approve{background:#238636;color:#fff}
  .btn-approve:hover{background:#2ea043}
  .btn-extend{background:#1f6feb;color:#fff}
  .btn-extend:hover{background:#388bfd}
  .btn-block{background:#b62324;color:#fff}
  .btn-block:hover{background:#da3633}
  .btn-delete{background:#30363d;color:#e6edf3}
  .btn-delete:hover{background:#484f58}
  .actions{display:flex;gap:6px;flex-wrap:wrap}
  .remain{color:#3fb950;font-size:11px}
  .expired-txt{color:#6e7681}
  #msg{margin-bottom:16px;padding:10px 14px;border-radius:6px;font-size:13px;display:none}
  .msg-ok{background:#0d4429;border:1px solid #238636;color:#3fb950}
  .msg-err{background:#3d0614;border:1px solid #da3633;color:#ff7b72}
  .refresh-btn{background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;margin-bottom:16px}
  .refresh-btn:hover{background:#30363d}
  .count{color:#8b949e;font-size:12px;margin-bottom:12px}
  .topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;flex-wrap:wrap}
  .empty{color:#8b949e;padding:24px 0}
  code{color:#79c0ff}
</style>
</head>
<body>
<h1>🔐 Strike Auth 관리자</h1>

<div id="msg"></div>

<div class="topbar">
  <button class="refresh-btn" id="refreshBtn">🔄 새로고침</button>
  <div class="count" id="count"></div>
</div>

<table>
  <thead>
    <tr>
      <th>IP</th>
      <th>이름</th>
      <th>연락처</th>
      <th>상태</th>
      <th>신청일시</th>
      <th>승인일시 / 잔여</th>
      <th>액션</th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>

<script>
const BASE = location.origin;

function getSecret() {
  return new URLSearchParams(location.search).get('secret') || '';
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function showMsg(text, ok = true) {
  const el = document.getElementById('msg');
  el.textContent = text;
  el.className = ok ? 'msg-ok' : 'msg-err';
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 3000);
}

function fmtDate(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  return d.toLocaleString('ko-KR', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function fmtRemain(approvedAt) {
  if (!approvedAt) return '-';
  const remain = (approvedAt + 86400000) - Date.now();
  if (remain <= 0) return '<span class="expired-txt">만료됨</span>';
  const h = Math.floor(remain / 3600000);
  const m = Math.floor((remain % 3600000) / 60000);
  return '<span class="remain">' + h + '시간 ' + m + '분 남음</span>';
}

function badgeHtml(status) {
  const map = {
    pending: 'badge-pending',
    approved: 'badge-approved',
    expired: 'badge-expired',
    blocked: 'badge-blocked'
  };
  const label = {
    pending: '대기중',
    approved: '승인됨',
    expired: '만료됨',
    blocked: '차단됨'
  };
  return '<span class="badge ' + (map[status] || '') + '">' + escapeHtml(label[status] || status) + '</span>';
}

async function api(path, body = null) {
  const secret = getSecret();
  const sep = path.includes('?') ? '&' : '?';

  const opts = {
    method: body ? 'POST' : 'GET',
    headers: {
      'Content-Type': 'application/json'
    }
  };

  if (body) {
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(BASE + path + sep + 'secret=' + encodeURIComponent(secret), opts);

  try {
    return await res.json();
  } catch (e) {
    return {
      error: 'JSON 응답 파싱 실패',
      status: res.status
    };
  }
}

async function doAction(action, ip) {
  if (action === 'delete' && !confirm(ip + ' 를 삭제하시겠습니까?')) return;
  if (action === 'block' && !confirm(ip + ' 를 차단하시겠습니까?')) return;

  const res = await api('/admin/' + action, { ip });

  if (res.success || res.deleted) {
    const actionLabel = {
      approve: '승인',
      extend: '연장',
      block: '차단',
      delete: '삭제'
    };
    showMsg(ip + ' → ' + (actionLabel[action] || action) + ' 완료');
    await loadList();
  } else {
    showMsg('실패: ' + (res.error || '알 수 없는 오류'), false);
  }
}

function renderActionButtons(r) {
  const buttons = [];

  if (r.status === 'pending' || r.status === 'expired') {
    buttons.push(
      '<button class="btn-sm btn-approve" data-action="approve" data-ip="' + escapeHtml(r.ip) + '">승인</button>'
    );
  }

  if (r.status === 'approved') {
    buttons.push(
      '<button class="btn-sm btn-extend" data-action="extend" data-ip="' + escapeHtml(r.ip) + '">+24h</button>'
    );
  }

  if (r.status !== 'blocked') {
    buttons.push(
      '<button class="btn-sm btn-block" data-action="block" data-ip="' + escapeHtml(r.ip) + '">차단</button>'
    );
  } else {
    buttons.push(
      '<button class="btn-sm btn-approve" data-action="approve" data-ip="' + escapeHtml(r.ip) + '">차단해제</button>'
    );
  }

  buttons.push(
    '<button class="btn-sm btn-delete" data-action="delete" data-ip="' + escapeHtml(r.ip) + '">삭제</button>'
    );
  return buttons.join('');
}

async function loadList() {
  const data = await api('/admin/list');

  if (!Array.isArray(data)) {
    showMsg('불러오기 실패: ' + (data.error || '알 수 없는 오류'), false);
    return;
  }

  const pending = data.filter(r => r.status === 'pending').length;
  const approved = data.filter(r => r.status === 'approved').length;

  document.getElementById('count').textContent =
    '전체 ' + data.length + '건 | 대기 ' + pending + ' | 승인 ' + approved;

  const tbody = document.getElementById('tbody');

  if (data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">등록된 신청 내역이 없습니다.</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(r => {
    const ip = escapeHtml(r.ip || '-');
    const name = escapeHtml(r.name || '-');
    const contact = escapeHtml(r.contact || '-');

    return '' +
      '<tr>' +
        '<td><code>' + ip + '</code></td>' +
        '<td>' + name + '</td>' +
        '<td>' + contact + '</td>' +
        '<td>' + badgeHtml(r.status) + '</td>' +
        '<td>' + fmtDate(r.appliedAt) + '</td>' +
        '<td>' + fmtDate(r.approvedAt) + '<br>' + (r.status === 'approved' ? fmtRemain(r.approvedAt) : '') + '</td>' +
        '<td><div class="actions">' + renderActionButtons(r) + '</div></td>' +
      '</tr>';
  }).join('');

  document.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.action;
      const ip = btn.dataset.ip;
      await doAction(action, ip);
    });
  });
}

document.getElementById('refreshBtn').addEventListener('click', loadList);
loadList();
</script>
</body>
</html>`;
