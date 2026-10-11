import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { setTransport } from "../api";
import { bitsPerSecond } from "../components/RateChart";
import { Overview } from "./Overview";

function incident(index: number, severity: string) {
  return {
    incident_id: `0192f3c4-0000-7000-8000-00000000000${index}`,
    incident_number: `WNM-2026-00000${index}`,
    title: `<b>attack ${index}</b>`,
    state: "open",
    severity,
    priority: "P1",
    category: "volumetric",
    direction: "incoming",
    target_type: "host",
    target_id: "203.0.113.10",
    opened_at: "2026-10-12T00:00:00Z",
    last_detected_at: "2026-10-12T00:00:00Z",
    assigned_user_id: null,
    assigned_team_id: null,
    version: 1,
  };
}

function api(trafficTenant: boolean) {
  setTransport(async (input) => {
    const path = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
    if (path.startsWith("/api/v1/incidents")) {
      return json({
        items: [incident(1, "critical"), incident(2, "critical"), incident(3, "minor")],
        next_cursor: null,
        has_more: false,
      });
    }
    if (!trafficTenant) {
      return json({ status: 404, error: "api.not_found", title: "Not found" }, 404);
    }
    if (path.startsWith("/api/v1/traffic/summary")) {
      return json({
        from: "2026-10-12T00:00:00Z",
        to: "2026-10-12T01:00:00Z",
        step_seconds: 10,
        points: [
          { time: "2026-10-12T00:00:00Z", ipv4_bps: 1e9, ipv6_bps: 2e8, ipv4_pps: 1, ipv6_pps: 1 },
          { time: "2026-10-12T00:00:10Z", ipv4_bps: 2e9, ipv6_bps: 5e8, ipv4_pps: 1, ipv6_pps: 1 },
        ],
      });
    }
    if (path.startsWith("/api/v1/traffic/top")) {
      return json({ items: [{ key: "<i>203.0.113.10</i>", bytes: 1000, packets: 10, flows: 1 }] });
    }
    return json({
      items: [
        { exporter: "192.0.2.1", last_seen: "2026-10-12T00:59:00Z", silent_seconds: 30, bps: 800, pps: 1 },
        { exporter: "192.0.2.2", last_seen: "2026-10-11T23:00:00Z", silent_seconds: 7200, bps: 0, pps: 0 },
      ],
    });
  });
}

function show() {
  return render(
    <MemoryRouter>
      <Overview />
    </MemoryRouter>,
  );
}

describe("the overview", () => {
  it("counts active incidents, charts traffic and calls out silent exporters", async () => {
    api(true);
    const { container } = show();
    expect(await screen.findByText("Traffic, last hour")).toBeTruthy();
    const tiles = screen.getByRole("list", { name: "Active incidents by severity" });
    expect(tiles.textContent).toContain("critical2");
    expect(tiles.textContent).toContain("minor1");
    expect(screen.getByText(bitsPerSecond(2.5e9))).toBeTruthy();
    expect(screen.getByText(/silent 120 min/)).toBeTruthy();
    expect(screen.getByText("✓ reporting")).toBeTruthy();
    expect(container.querySelectorAll("polyline")).toHaveLength(2);
    // Hostile text from the API stays text.
    expect(screen.getByText("<i>203.0.113.10</i>")).toBeTruthy();
    expect(container.querySelector("b, i")).toBeNull();
    // No inline style anywhere: the CSP would refuse it.
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("shows incidents alone to a tenant that is not the traffic tenant", async () => {
    api(false);
    show();
    expect(await screen.findByText("Traffic is not available to this tenant.")).toBeTruthy();
    expect(screen.queryByText("Exporters")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("formats rates in decimal units", () => {
    expect(bitsPerSecond(950)).toBe("950 bit/s");
    expect(bitsPerSecond(1_500_000)).toBe("1.5 Mbit/s");
    expect(bitsPerSecond(2.5e9)).toBe("2.5 Gbit/s");
  });
});
