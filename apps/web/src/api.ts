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

export interface Incident {
  incident_id: string;
  incident_number: string;
  title: string;
  description: string | null;
  state: string;
  severity: string;
  severity_source: string;
  maximum_detected_severity: string;
  priority: string;
  category: string;
  direction: string;
  target_type: string;
  target_id: string;
  opened_at: string;
  first_detected_at: string;
  last_detected_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  closure_reason: string | null;
  reopen_count: number;
  assigned_user_id: string | null;
  assigned_team_id: string | null;
  suppression: { by: string; reason: string; until: string } | null;
  tags: Record<string, string>;
  mitigation_status: string;
  notification_status: string;
  version: number;
}

export interface TimelineEntry {
  timeline_id: string;
  occurred_at: string;
  entry_type: string;
  actor: string;
  payload: unknown;
}

export interface Note {
  note_index: number;
  author: string;
  body: string;
  visibility: string;
  supersedes_note_index: number | null;
  superseded_by_note_index: number | null;
  redacted: boolean;
}

export interface WhoAmI {
  tenant_id: string;
  actor_type: string;
  actor_id: string;
  role: string;
  permissions: string[];
}

/** A fresh key per user action: a retry of the same request replays. */
export function idempotencyKey(): string {
  return `ui-${crypto.randomUUID()}`;
}

const incidentPath = (id: string) => `/api/v1/incidents/${encodeURIComponent(id)}`;

export function getIncident(id: string): Promise<Incident> {
  return request<Incident>("GET", incidentPath(id));
}

export async function getTimeline(id: string): Promise<TimelineEntry[]> {
  const page = await request<{ items: TimelineEntry[] }>(
    "GET",
    `${incidentPath(id)}/timeline?limit=200`,
  );
  return page.items;
}

export async function getNotes(id: string): Promise<Note[]> {
  const list = await request<{ items: Note[] }>("GET", `${incidentPath(id)}/notes`);
  return list.items;
}

export function whoAmI(): Promise<WhoAmI> {
  return request<WhoAmI>("GET", "/api/v1/whoami");
}

/**
 * One state transition or field change: the version the operator saw, and
 * a new idempotency key. A stale version is refused by the API (409).
 */
export function transition(
  id: string,
  action: string,
  version: number,
  fields: Record<string, unknown> = {},
): Promise<Incident> {
  return request<Incident>(
    "POST",
    `${incidentPath(id)}/${action}`,
    { expected_version: version, ...fields },
    { "Idempotency-Key": idempotencyKey() },
  );
}

export function addNote(id: string, body: string): Promise<Incident> {
  return request<Incident>("POST", `${incidentPath(id)}/notes`, { body }, {
    "Idempotency-Key": idempotencyKey(),
  });
}

export function editNote(id: string, index: number, body: string): Promise<Incident> {
  return request<Incident>("POST", `${incidentPath(id)}/notes/${index}/edit`, { body }, {
    "Idempotency-Key": idempotencyKey(),
  });
}

export function redactNote(id: string, index: number, reason: string): Promise<Incident> {
  return request<Incident>("POST", `${incidentPath(id)}/notes/${index}/redact`, { reason }, {
    "Idempotency-Key": idempotencyKey(),
  });
}

export interface TrafficPoint {
  time: string;
  ipv4_bps: number;
  ipv6_bps: number;
  ipv4_pps: number;
  ipv6_pps: number;
}

export interface TrafficSummary {
  from: string;
  to: string;
  step_seconds: number;
  points: TrafficPoint[];
}

export interface TopEntry {
  key: string;
  bytes: number;
  packets: number;
  flows: number;
}

export interface Exporter {
  exporter: string;
  last_seen: string;
  silent_seconds: number;
  bps: number;
  pps: number;
}

/**
 * Traffic is deployment-wide and served to one tenant only (ADR 0042).
 * Anyone else gets 404, which this returns as `null`: not an error, just
 * nothing to show.
 */
async function traffic<T>(path: string): Promise<T | null> {
  try {
    return await request<T>("GET", path);
  } catch (error) {
    if (error instanceof ApiError && error.problem.status === 404) {
      return null;
    }
    throw error;
  }
}

export function trafficSummary(): Promise<TrafficSummary | null> {
  return traffic<TrafficSummary>("/api/v1/traffic/summary");
}

export async function topHosts(limit: number): Promise<TopEntry[] | null> {
  const list = await traffic<{ items: TopEntry[] }>(
    `/api/v1/traffic/top?dimension=host&limit=${limit}`,
  );
  return list === null ? null : list.items;
}

export async function exporters(): Promise<Exporter[] | null> {
  const list = await traffic<{ items: Exporter[] }>("/api/v1/exporters");
  return list === null ? null : list.items;
}

// --- Mitigations (ADR 0050). The API records and decides; the mitigator
// announces. Nothing here speaks to GoBGP. ---

export interface FlowMatch {
  protocol?: number;
  source?: string;
  source_port?: number;
  destination_port?: number;
}

export interface Mitigation {
  mitigation_id: string;
  tenant_id: string;
  incident_id: string | null;
  prefix: string;
  action: string;
  flow: FlowMatch | null;
  bytes_per_second: number | null;
  reason: string;
  duration_seconds: number;
  state: string;
  version: number;
  requested_by: string;
  approved_by: string | null;
  dry_run: boolean | null;
  withdrawal_cause: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
  approved_at: string | null;
  active_since: string | null;
  expires_at: string | null;
  ended_at: string | null;
}

/** What a request carries. There is no route attribute: those are the deployment's. */
export interface MitigationRequest {
  prefix: string;
  action: string;
  reason: string;
  duration_seconds: number;
  incident_id?: string;
  flow?: FlowMatch;
  bytes_per_second?: number;
}

export interface KillSwitch {
  engaged: boolean;
  version: number;
  changed_at: string | null;
  changed_by: string | null;
  reason: string | null;
}

export interface BgpPeer {
  neighbor_address: string;
  peer_asn: number;
  session_state: string;
  updated_at: string;
}

const mitigationPath = (id: string) => `/api/v1/mitigations/${encodeURIComponent(id)}`;

export async function listMitigations(live: boolean): Promise<Mitigation[]> {
  const query = new URLSearchParams({ limit: "200", live: String(live) });
  const list = await request<{ items: Mitigation[] }>("GET", `/api/v1/mitigations?${query.toString()}`);
  return list.items;
}

export function requestMitigation(body: MitigationRequest): Promise<Mitigation> {
  return request<Mitigation>("POST", "/api/v1/mitigations", body, {
    "Idempotency-Key": idempotencyKey(),
  });
}

/** Approve, reject or withdraw, with the version the operator saw. */
export function decideMitigation(
  id: string,
  decision: "approve" | "reject" | "withdraw",
  version: number,
  reason?: string,
): Promise<Mitigation> {
  return request<Mitigation>(
    "POST",
    `${mitigationPath(id)}/${decision}`,
    { expected_version: version, ...(reason === undefined ? {} : { reason }) },
    { "Idempotency-Key": idempotencyKey() },
  );
}

export function getKillSwitch(): Promise<KillSwitch> {
  return request<KillSwitch>("GET", "/api/v1/mitigation-controls/kill-switch");
}

/** Engages only: releasing is host-only, and no session may do it. */
export function engageKillSwitch(reason: string): Promise<KillSwitch> {
  return request<KillSwitch>("PUT", "/api/v1/mitigation-controls/kill-switch", {
    engaged: true,
    reason,
  });
}

export async function bgpPeers(): Promise<BgpPeer[]> {
  const list = await request<{ items: BgpPeer[] }>("GET", "/api/v1/bgp/peers");
  return list.items;
}

