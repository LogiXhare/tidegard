// The UI's only way to the API (ADR 0044). Same origin, so the session
// cookie travels by itself; the page never holds a token after sign-in.
// Every request that changes anything carries the session's CSRF value
// (ADR 0043).

export interface Problem {
  status: number;
  error: string;
  title: string;
  detail?: string;
}

export class ApiError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail ?? problem.title);
    this.problem = problem;
  }
}

export interface Session {
  csrf_token: string;
  expires_at: string;
  idle_timeout_seconds: number;
  tenant_id: string;
  actor_id: string;
  role: string;
}

export interface IncidentSummary {
  incident_id: string;
  incident_number: string;
  title: string;
  state: string;
  severity: string;
  priority: string;
  category: string;
  direction: string;
  target_type: string;
  target_id: string;
  opened_at: string;
  last_detected_at: string;
  assigned_user_id: string | null;
  assigned_team_id: string | null;
  version: number;
}

export interface IncidentPage {
  items: IncidentSummary[];
  next_cursor: string | null;
  has_more: boolean;
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** The CSRF value of the current session, set at sign-in or on load. */
let csrf: string | null = null;

export function setCsrf(value: string | null): void {
  csrf = value;
}

type Fetch = typeof fetch;
let transport: Fetch = (...args) => fetch(...args);

/** Tests replace the network. */
export function setTransport(next: Fetch): void {
  transport = next;
}

export async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...extraHeaders };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (!SAFE_METHODS.has(method) && csrf !== null) {
    headers["X-WNM-CSRF"] = csrf;
  }
  const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const response = await transport(path, init);
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  const parsed: unknown = text === "" ? null : JSON.parse(text);
  if (!response.ok) {
    const problem = (parsed ?? {}) as Partial<Problem>;
    throw new ApiError({
      status: response.status,
      error: problem.error ?? "api.unknown",
      title: problem.title ?? response.statusText,
      ...(problem.detail === undefined ? {} : { detail: problem.detail }),
    });
  }
  return parsed as T;
}

/** Exchanges a token for a session. The token is not kept anywhere. */
export async function signIn(token: string): Promise<Session> {
  const session = await request<Session>("POST", "/api/v1/session", { token });
  setCsrf(session.csrf_token);
  return session;
}

export async function currentSession(): Promise<Session | null> {
  try {
    const session = await request<Session>("GET", "/api/v1/session");
    setCsrf(session.csrf_token);
    return session;
  } catch (error) {
    if (error instanceof ApiError && error.problem.status === 401) {
      return null;
    }
    throw error;
  }
}

export async function signOut(): Promise<void> {
  await request<undefined>("DELETE", "/api/v1/session");
  setCsrf(null);
}

export async function listIncidents(states: string[]): Promise<IncidentPage> {
  const query = new URLSearchParams({ limit: "100" });
  for (const state of states) {
    query.append("state", state);
  }
  return request<IncidentPage>("GET", `/api/v1/incidents?${query.toString()}`);
}
