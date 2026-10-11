import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { setTransport } from "../api";
import { IncidentDetail } from "./IncidentDetail";

const ID = "0192f3c4-0000-7000-8000-000000000001";
const HOSTILE = '<img src=x onerror="window.__pwned=1">';

function incident(overrides: Record<string, unknown> = {}) {
  return {
    incident_id: ID,
    incident_number: "WNM-2026-000001",
    title: HOSTILE,
    description: "<script>window.__pwned=1</script>",
    state: "open",
    severity: "major",
    severity_source: "detection",
    maximum_detected_severity: "major",
    priority: "P2",
    category: "volumetric",
    direction: "incoming",
    target_type: "host",
    target_id: "203.0.113.10",
    opened_at: "2026-10-12T00:00:00Z",
    first_detected_at: "2026-10-12T00:00:00Z",
    last_detected_at: "2026-10-12T00:00:00Z",
    acknowledged_at: null,
    resolved_at: null,
    closed_at: null,
    closure_reason: null,
    reopen_count: 0,
    assigned_user_id: null,
    assigned_team_id: null,
    suppression: null,
    tags: {},
    mitigation_status: "none",
    notification_status: "none",
    version: 4,
    ...overrides,
  };
}

interface Call {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

function api(permissions: string[], onPost?: (call: Call) => Response): Call[] {
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
    if (call.method === "POST") {
      return onPost?.(call) ?? json(incident({ version: 5 }));
    }
    if (call.path === "/api/v1/whoami") {
      return json({ tenant_id: "acme", actor_type: "operator", actor_id: "alice", role: "x", permissions });
    }
    if (call.path.endsWith("/notes")) {
      return json({
        items: [
          {
            note_index: 0,
            author: "bob",
            body: HOSTILE,
            visibility: "internal",
            supersedes_note_index: null,
            superseded_by_note_index: null,
            redacted: false,
          },
        ],
      });
    }
    if (call.path.includes("/timeline")) {
      return json({ items: [], next_cursor: null, has_more: false });
    }
    return json(incident());
  });
  return calls;
}

function show() {
  return render(
    <MemoryRouter initialEntries={[`/incidents/${ID}`]}>
      <Routes>
        <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  delete (window as unknown as Record<string, unknown>)["__pwned"];
});

describe("an incident", () => {
  it("shows hostile title, description and note bodies as text", async () => {
    api(["incident.read"]);
    const { container } = show();
    expect(await screen.findAllByText(HOSTILE)).toHaveLength(2);
    expect(screen.getByText("<script>window.__pwned=1</script>")).toBeTruthy();
    expect(container.querySelector("img, script")).toBeNull();
    expect((window as unknown as Record<string, unknown>)["__pwned"]).toBeUndefined();
  });

  it("offers a viewer no action at all", async () => {
    api(["incident.read", "incident.list"]);
    show();
    await screen.findAllByText(HOSTILE);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("acknowledges with the version seen and a fresh key", async () => {
    const calls = api(["incident.read", "incident.acknowledge", "incident.investigate"]);
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(calls.some((call) => call.method === "POST")).toBe(true));
    const post = calls.find((call) => call.method === "POST");
    expect(post?.path).toBe(`/api/v1/incidents/${ID}/acknowledge`);
    expect(post?.body).toEqual({ expected_version: 4 });
    expect(post?.headers["Idempotency-Key"]).toMatch(/^ui-[0-9a-f-]{36}$/);
  });

  it("explains a version conflict instead of retrying", async () => {
    const calls = api(["incident.read", "incident.acknowledge"], () =>
      new Response(
        JSON.stringify({ status: 409, error: "incident.version_conflict", title: "Version conflict" }),
        { status: 409 },
      ),
    );
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Someone else changed");
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
  });

  it("asks before lowering severity, and sends nothing when declined", async () => {
    const calls = api(["incident.read", "incident.severity.change"]);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    show();
    fireEvent.change(await screen.findByLabelText("Severity"), { target: { value: "minor" } });
    fireEvent.click(screen.getByRole("button", { name: "Change severity" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Lower WNM-2026-000001 from major to minor"));
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });
});
