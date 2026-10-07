/**
 * @system runtime-auth-flow
 * @status handwritten
 */
import { getSession } from "@teamscala/auth/get-session";
import { getServerClient } from "@teamscala/orpc/server-client-registry";
import { createLogger } from "@teamscala/logger/creator";
import { normalizeError } from "@teamscala/os/errors/adapter-error-normalizer";

const logger = createLogger({ service: "runtime-auth-flow" });

export interface OrgReq {
	ok: true;
	orgId: string;
	/** Connecting user (for personal-scope binds). Absent if the session has no user id. */
	userId?: string;
}
export interface OrgDenied {
	ok: false;
	res: Response;
}

/**
 * Authorise a session user to act on orgId. `super_admin` manages any org; every
 * other caller must be a member (portal-style authz, matching
 * enforcePageAccessPolicy). Returns a 403/500 Response if denied, null if
 * allowed. Shared by requireOrg (org from the query param) + the OAuth callback
 * (org from the signed state) — both reach the SAME membership gate.
 */
export async function authoriseOrgMembership(
	sessionUser: { id: string; role: string | null },
	orgId: string,
): Promise<Response | null> {
	if (sessionUser.role === "super_admin") return null;
	try {
		const orpc = (await getServerClient()) as never as {
			member: {
				findFirst: (args: {
					where: { user_id: string; organization_id: string };
					select: { id: true };
				}) => Promise<{ id: string } | null>;
			};
		};
		const membership = await orpc.member.findFirst({
			where: { user_id: sessionUser.id, organization_id: orgId },
			select: { id: true },
		});
		if (!membership) {
			return Response.json({ error: "not a member of organisation" }, { status: 403 });
		}
		return null;
	} catch (error) {
		logger.error("[authoriseOrgMembership] check failed", { orgId, error: normalizeError([], error).message });
		return Response.json({ error: "authorisation check failed" }, { status: 500 });
	}
}

/**
 * Read one cookie value off the request.
 *
 * Used for the connect-connection id the QR image endpoint mints (see
 * telegramConnectQrImage): the browser carries it back on the status poll, so
 * the page never has to hold it and it stays out of the cached SSR loader graph.
 * Returns "" when absent, which the caller treats as "no connection in flight".
 */
export function readConnectCookie(req: Request, name: string): string {
	const header = req.headers.get("cookie") ?? "";
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() !== name) continue;
		return decodeURIComponent(part.slice(eq + 1).trim());
	}
	return "";
}

/** Require a valid session + an active organisation on the request. The org is
 *  session-derived (session.activeOrganizationId) for regular users — never the
 *  query/form param that previously drove the hijack. The platform super-admin
 *  (role "admin") can act on ANY org, so for super-admin the explicit
 *  organisationId query param is honored (the portal passes the target
 *  organisation_profile id; this is how the super-admin manages orgs they're not
 *  a direct member of — the platform's orgs are organisation_profile rows, not all
 *  of which carry BetterAuth memberships). */
export async function requireOrg(req: Request): Promise<OrgReq | OrgDenied> {
	const session = await getSession(req.headers);
	if (!session?.user) {
		return { ok: false, res: Response.json({ error: "unauthorized" }, { status: 401 }) };
	}
	// The portal tracks the active org by URL PATH (/${websiteId}/${orgId}/…),
	// never calling better-auth setActive — so session.activeOrganizationId is
	// always null + is NOT a usable org source. The viewed org reaches this
	// gateway only as the `organisationId` query param the portal's connect
	// button passes. Derive the org from THERE, then AUTHORISE via the shared
	// membership gate. The previous read of activeOrganizationId + the
	// `role === "admin"` gate (the platform role is `super_admin`) 403'd EVERY
	// portal user — connect flows only ever worked on paper. The OAuth CALLBACK
	// does NOT use this (its org comes from the signed state, not the query).
	// See reference/connect-messaging-number.md.
	const orgId = new URL(req.url).searchParams.get("organisationId") ?? "";
	if (!orgId) {
		return { ok: false, res: Response.json({ error: "missing organisationId" }, { status: 400 }) };
	}
	const denied = await authoriseOrgMembership(session.user, orgId);
	if (denied) return { ok: false, res: denied };
	return { ok: true, orgId, userId: session.user.id };
}

/** Confine OAuth callback redirects to the platform surface (prevent open-
 *  redirect abuse of the callbackUrl param). Allows any host under the apex
 *  cookie domain (e.g. "*.scala.business"). */
export function isSafeCallbackUrl(callbackUrl: string, cookieDomain: string): boolean {
	try {
		const u = new URL(callbackUrl);
		return u.protocol === "https:" && u.hostname.endsWith(cookieDomain);
	} catch {
		return false;
	}
}
