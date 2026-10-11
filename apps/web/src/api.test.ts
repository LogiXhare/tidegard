import { afterEach, describe, expect, it } from "vitest";

import { ApiError, listIncidents, setCsrf, setTransport, signIn, signOut } from "./api";

interface Sent {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string | undefined;
}

function recorder(responses: Response[]): Sent[] {
  const sent: Sent[] = [];
  setTransport(async (input, init) => {
    sent.push({
      method: init?.method ?? "GET",
      path: String(input),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body as string | undefined,
    });
    const next = responses.shift();
    if (next === undefined) throw new Error("no response queued");
    return next;
  });
  return sent;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const SESSION = {
  csrf_token: "c".repeat(64),
  expires_at: "2026-10-12T12:00:00Z",
  idle_timeout_seconds: 1800,
  tenant_id: "acme",
  actor_id: "alice",
  role: "operator",
};

afterEach(() => setCsrf(null));

describe("the API client", () => {
  it("sends the token once, then only the CSRF value on changes", async () => {
    const sent = recorder([
      json(201, SESSION),
      json(200, { items: [], next_cursor: null, has_more: false }),
      new Response(null, { status: 204 }),
    ]);
    await signIn("wnm_secret");
    await listIncidents(["open"]);
    await signOut();

    expect(sent[0]?.body).toBe(JSON.stringify({ token: "wnm_secret" }));
    expect(sent[1]?.headers["X-WNM-CSRF"]).toBeUndefined();
    expect(sent[1]?.path).toBe("/api/v1/incidents?limit=100&state=open");
    expect(sent[2]?.method).toBe("DELETE");
    expect(sent[2]?.headers["X-WNM-CSRF"]).toBe(SESSION.csrf_token);
    for (const request of sent.slice(1)) {
      expect(JSON.stringify(request)).not.toContain("wnm_secret");
      expect(request.headers["Authorization"]).toBeUndefined();
    }
  });

  it("turns a problem document into an ApiError", async () => {
    recorder([json(401, { status: 401, error: "api.unauthenticated", title: "Authentication required" })]);
    const failure = await signIn("wnm_bad").catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).problem.error).toBe("api.unauthenticated");
  });
});
