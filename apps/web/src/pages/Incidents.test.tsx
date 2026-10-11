// T-08 in the UI: hostile text from the API renders as text and never as
// markup or script.
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";

import { setTransport } from "../api";
import { Incidents } from "./Incidents";

const HOSTILE = [
  '<img src=x onerror="window.__pwned=1">',
  "<script>window.__pwned=1</script>",
  '"><svg onload="window.__pwned=1">',
  "javascript:window.__pwned=1",
];

function incident(index: number, title: string) {
  return {
    incident_id: `0192f3c4-0000-7000-8000-00000000000${index}`,
    incident_number: `WNM-2026-00000${index}`,
    title,
    state: "open",
    severity: "critical",
    priority: "P1",
    category: "volumetric",
    direction: "incoming",
    target_type: "host",
    target_id: title,
    opened_at: "2026-10-12T00:00:00Z",
    last_detected_at: "2026-10-12T00:00:00Z",
    assigned_user_id: title,
    assigned_team_id: null,
    version: 1,
  };
}

afterEach(() => {
  delete (window as unknown as Record<string, unknown>)["__pwned"];
});

describe("the incident list", () => {
  it("renders hostile titles, targets and assignees as text", async () => {
    setTransport(async () =>
      new Response(
        JSON.stringify({
          items: HOSTILE.map((title, index) => incident(index, title)),
          next_cursor: null,
          has_more: false,
        }),
        { status: 200 },
      ),
    );
    const { container } = render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    for (const title of HOSTILE) {
      const cells = await screen.findAllByText(title);
      expect(cells.length).toBe(3);
    }
    expect(container.querySelector("img, script, svg, iframe")).toBeNull();
    expect((window as unknown as Record<string, unknown>)["__pwned"]).toBeUndefined();
  });

  it("shows severity as a word and a shape, never colour alone", async () => {
    setTransport(async () =>
      new Response(
        JSON.stringify({ items: [incident(1, "UDP flood")], next_cursor: null, has_more: false }),
        { status: 200 },
      ),
    );
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    const severity = await screen.findByText(/critical/);
    expect(severity.textContent).toContain("▲");
  });
});
