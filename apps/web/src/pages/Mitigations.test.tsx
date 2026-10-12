import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { setTransport } from "../api";
import { Mitigations } from "./Mitigations";

const ID = "0192f3c4-0000-7000-8000-0000000000aa";
const HOSTILE = '<img src=x onerror="window.__pwned=1">';

function mitigation(overrides: Record<string, unknown> = {}) {
  return {
    mitigation_id: ID,
    tenant_id: "acme",
    incident_id: null,
    prefix: "203.0.113.9/32",
    action: "rtbh",
    flow: null,
    bytes_per_second: null,
    reason: HOSTILE,
    duration_seconds: 1800,
    state: "requested",
    version: 2,
    requested_by: "bob",
    approved_by: null,
    dry_run: null,
    withdrawal_cause: null,
    last_error: null,
    created_at: "2026-10-12T00:00:00Z",
    updated_at: "2026-10-12T00:00:00Z",
    approved_at: null,
    active_since: null,
    expires_at: null,
    ended_at: null,
    ...overrides,
  };
}

interface Call {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

interface Stand {
  permissions: string[];
  items?: unknown[];
  engaged?: boolean;
  peersSeen?: string;
  onWrite?: (call: Call) => Response | undefined;
}

function api(stand: Stand): Call[] {
  const calls: Call[] = [];
  setTransport(async (input, init) => {
    const call: Call = {
      method: init?.method ?? "GET",
      path: String(input),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body === undefined ? undefined : JSON.parse(init.body as string),
    };
    calls.push(call);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    if (call.method !== "GET") {
      return stand.onWrite?.(call) ?? json(mitigation({ state: "approved", version: 3 }));
    }
    if (call.path === "/api/v1/whoami") {
      return json({ tenant_id: "acme", actor_type: "operator", actor_id: "alice", role: "x", permissions: stand.permissions });
    }
    if (call.path.startsWith("/api/v1/mitigations?")) {
      return json({ items: stand.items ?? [mitigation()] });
    }
    if (call.path === "/api/v1/mitigation-controls/kill-switch") {
      return json({
        engaged: stand.engaged ?? false,
        version: 1,
        changed_at: stand.engaged === true ? "2026-10-12T00:00:00Z" : null,
        changed_by: stand.engaged === true ? "lead" : null,
        reason: stand.engaged === true ? HOSTILE : null,
      });
    }
    if (call.path === "/api/v1/bgp/peers") {
      return json({
        items: [
          {
            neighbor_address: "192.0.2.254",
            peer_asn: 64512,
            session_state: "established",
            updated_at: stand.peersSeen ?? new Date().toISOString(),
          },
        ],
      });
    }
    return json({ status: 404, error: "api.not_found", title: "Not found" }, 404);
  });
  return calls;
}

const READ = ["mitigation.read"];
const LEAD = ["mitigation.read", "mitigation.request", "mitigation.approve", "mitigation.withdraw", "mitigation.kill_switch.engage"];

function show(path = "/mitigations") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/mitigations" element={<Mitigations />} />
      </Routes>
    </MemoryRouter>,
  );
}

const writes = (calls: Call[]) => calls.filter((call) => call.method !== "GET");

afterEach(() => {
  vi.restoreAllMocks();
  delete (window as unknown as Record<string, unknown>)["__pwned"];
});

describe("the mitigations page", () => {
  it("shows hostile reasons as text and offers a viewer nothing to do", async () => {
    api({ permissions: READ, engaged: true });
    const { container } = show();
    expect(await screen.findAllByText(HOSTILE)).toHaveLength(2);
    expect(container.querySelector("img, script")).toBeNull();
    expect((window as unknown as Record<string, unknown>)["__pwned"]).toBeUndefined();
    expect(screen.getByRole("status").textContent).toContain("Kill switch engaged");
    expect(screen.queryByRole("button", { name: /Approve|Reject|Withdraw|Request|Engage/ })).toBeNull();
    expect(screen.queryByRole("region", { name: "BGP peers" })).toBeNull();
  });

  it("approves only after asking, with the version seen and a fresh key", async () => {
    const calls = api({ permissions: LEAD });
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    show();
    const approve = await screen.findByRole("button", { name: "Approve" });
    fireEvent.click(approve);
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Approve rtbh of 203.0.113.9/32, requested by bob"));
    expect(writes(calls)).toHaveLength(0);
    fireEvent.click(approve);
    await waitFor(() => expect(writes(calls)).toHaveLength(1));
    const [post] = writes(calls);
    expect(post?.path).toBe(`/api/v1/mitigations/${ID}/approve`);
    expect(post?.body).toEqual({ expected_version: 2 });
    expect(post?.headers["Idempotency-Key"]).toMatch(/^ui-[0-9a-f-]{36}$/);
  });

  it("withdraws an active mitigation with a reason, after asking", async () => {
    const calls = api({ permissions: LEAD, items: [mitigation({ state: "active", version: 5 })] });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    show();
    fireEvent.change(await screen.findByLabelText("Withdraw"), { target: { value: "attack over" } });
    fireEvent.click(screen.getByRole("button", { name: "Withdraw" }));
    await waitFor(() => expect(writes(calls)).toHaveLength(1));
    expect(writes(calls)[0]?.body).toEqual({ expected_version: 5, reason: "attack over" });
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("requests from an incident's prefill without route attributes", async () => {
    const calls = api({ permissions: LEAD, items: [] });
    show(`/mitigations?incident=inc-1&prefix=${encodeURIComponent("203.0.113.9/32")}`);
    const form = await screen.findByRole("form", { name: "Request a mitigation" });
    expect((within(form).getByLabelText("Prefix") as HTMLInputElement).value).toBe("203.0.113.9/32");
    fireEvent.change(within(form).getByLabelText("Action"), { target: { value: "flowspec_rate_limit" } });
    fireEvent.change(within(form).getByLabelText("Protocol"), { target: { value: "17" } });
    fireEvent.change(within(form).getByLabelText("Bytes per second"), { target: { value: "125000" } });
    fireEvent.change(within(form).getByLabelText("Request reason"), { target: { value: "dns flood" } });
    fireEvent.click(within(form).getByRole("button", { name: "Request" }));
    await waitFor(() => expect(writes(calls)).toHaveLength(1));
    const [post] = writes(calls);
    expect(post?.path).toBe("/api/v1/mitigations");
    expect(post?.body).toEqual({
      prefix: "203.0.113.9/32",
      action: "flowspec_rate_limit",
      reason: "dns flood",
      duration_seconds: 1800,
      incident_id: "inc-1",
      flow: { protocol: 17 },
      bytes_per_second: 125000,
    });
    expect(post?.headers["Idempotency-Key"]).toMatch(/^ui-/);
  });

  it("explains a version conflict instead of retrying", async () => {
    const calls = api({
      permissions: LEAD,
      onWrite: () =>
        new Response(JSON.stringify({ status: 409, error: "mitigation.version_conflict", title: "Version conflict" }), {
          status: 409,
        }),
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Someone else changed");
    expect(writes(calls)).toHaveLength(1);
  });

  it("engages the kill switch only when confirmed, and never offers a release", async () => {
    const calls = api({ permissions: LEAD });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    show();
    fireEvent.change(await screen.findByLabelText("Engage kill switch"), { target: { value: "storm" } });
    fireEvent.click(screen.getByRole("button", { name: "Engage kill switch" }));
    expect(confirm).toHaveBeenCalled();
    expect(writes(calls)).toHaveLength(0);
    confirm.mockReturnValue(true);
    fireEvent.change(screen.getByLabelText("Engage kill switch"), { target: { value: "storm" } });
    fireEvent.click(screen.getByRole("button", { name: "Engage kill switch" }));
    await waitFor(() => expect(writes(calls)).toHaveLength(1));
    expect(writes(calls)[0]).toMatchObject({
      method: "PUT",
      path: "/api/v1/mitigation-controls/kill-switch",
      body: { engaged: true, reason: "storm" },
    });
    expect(screen.queryByRole("button", { name: /Release/ })).toBeNull();
  });

  it("calls out an old peer snapshot", async () => {
    api({ permissions: LEAD, peersSeen: "2020-01-01T00:00:00Z" });
    show();
    const peers = await screen.findByRole("region", { name: "BGP peers" });
    expect(within(peers).getByText("192.0.2.254")).toBeTruthy();
    expect(within(peers).getByRole("alert").textContent).toContain("may have stopped");
  });
});
