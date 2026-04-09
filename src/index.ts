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

export class MyDurableObject extends DurableObject<Env> {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
	}

	private normalizeRecord(record: unknown): AuthRecord | null {
		if (!record || typeof record !== "object") return null;

		const r = record as Partial<AuthRecord>;
		return {
			status: (r.status as AuthStatus) || "pending",
			name: String(r.name || "").slice(0, 30),
			contact: String(r.contact || "").slice(0, 50),
			appliedAt: Number(r.appliedAt || 0) || null,
			approvedAt: Number(r.approvedAt || 0) || null,
		};
	}

	private async getStoredRecord(): Promise<AuthRecord | null> {
		const record = await this.ctx.storage.get<AuthRecord>("record");
		return this.normalizeRecord(record);
	}

	private async putStoredRecord(record: AuthRecord): Promise<void> {
		await this.ctx.storage.put("record", this.normalizeRecord(record));
	}

	private async withExpiration(record: AuthRecord | null): Promise<AuthRecord | null> {
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
		return this.withExpiration(await this.getStoredRecord());
	}

	async apply(name: string, contact: string): Promise<{ status: string; record?: AuthRecord; error?: string }> {
		const safeName = String(name || "").trim().slice(0, 30);
		const safeContact = String(contact || "").trim().slice(0, 50);

		if (!safeName || !safeContact) {
			return { status: "error", error: "이름과 연락처를 입력해주세요." };
		}

		const existing = await this.withExpiration(await this.getStoredRecord());

		if (existing) {
			if (existing.status === "pending") return { status: "already_pending", record: existing };
			if (existing.status === "approved") return { status: "already_approved", record: existing };
			if (existing.status === "blocked") return { status: "blocked", record: existing };
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

	async approve(): Promise<{ success: true; record: AuthRecord }> {
		const existing = await this.withExpiration(await this.getStoredRecord());

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

	async extend(): Promise<{ success?: true; record?: AuthRecord; error?: string }> {
		const existing = await this.withExpiration(await this.getStoredRecord());
		if (!existing) {
			return { error: "존재하지 않는 IP" };
		}

		const updated: AuthRecord = {
			...existing,
			status: "approved",
			approvedAt: Date.now(),
		};

		await this.putStoredRecord(updated);
		return { success: true, record: updated };
	}

	async block(): Promise<{ success: true; record: AuthRecord }> {
		const existing = await this.withExpiration(await this.getStoredRecord());

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

		const getClientIp = () => {
			const ip = request.headers.get("CF-Connecting-IP");
			return ip ? ip.trim() : null;
		};

		const getStubByIp = (ip: string) => {
			const id = env.MY_DURABLE_OBJECT.idFromName(ip);
			return env.MY_DURABLE_OBJECT.get(id);
		};

		if (path === "/check" && method === "GET") {
			const ip = getClientIp();
			if (!ip) return json({ error: "IP 확인 불가" }, 400);

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

		if (path === "/apply" && method === "POST") {
			const ip = getClientIp();
			if (!ip) return json({ error: "IP 확인 불가" }, 400);

			const body = (await request.json().catch(() => ({}))) as {
				name?: string;
				contact?: string;
			};

			const stub = getStubByIp(ip);
			const result = await stub.apply(body.name || "", body.contact || "");

			return json(result, result.error ? 400 : 200);
		}

		if (path.startsWith("/admin/") && method === "POST") {
			if (!isAdmin()) return json({ error: "Unauthorized" }, 401);

			const body = (await request.json().catch(() => ({}))) as { ip?: string };
			const ip = String(body?.ip || "").trim();
			if (!ip) return json({ error: "IP 없음" }, 400);

			const stub = getStubByIp(ip);
			const action = path.replace("/admin/", "");

			if (action === "approve") {
				const result = await stub.approve();
				return json({ success: true, ip, ...result });
			}

			if (action === "extend") {
				const result = await stub.extend();
				return json(result.error ? { ip, ...result } : { success: true, ip, ...result }, result.error ? 404 : 200);
			}

			if (action === "block") {
				const result = await stub.block();
				return json({ success: true, ip, ...result });
			}

			if (action === "delete") {
				const result = await stub.deleteRecord();
				return json({ success: true, ip, ...result });
			}

			return json({ error: "알 수 없는 액션" }, 400);
		}

		return json({ error: "Not Found" }, 404);
	},
} satisfies ExportedHandler<Env>;
