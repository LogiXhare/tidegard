// The incident list: the NOC's first view. Titles, targets and assignees
// are untrusted text, and React renders them only as text (T-08).
import { useEffect, useState } from "react";

import { ApiError, listIncidents } from "../api";
import type { IncidentSummary } from "../api";
import { Severity } from "../components/Severity";

const ACTIVE = ["open", "acknowledged", "investigating", "monitoring", "recovering"];
const VIEWS: Record<string, string[]> = {
  active: ACTIVE,
  resolved: ["resolved"],
  closed: ["closed"],
  all: [],
};

const REFRESH_MS = 30_000;

export function Incidents() {
  const [view, setView] = useState("active");
  const [items, setItems] = useState<IncidentSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () => {
      listIncidents(VIEWS[view] ?? ACTIVE)
        .then((page) => {
          if (!live) return;
          setItems(page.items);
          setError(null);
        })
        .catch((failure: unknown) => {
          if (!live) return;
          setError(
            failure instanceof ApiError ? failure.problem.title : "The API could not be reached.",
          );
        });
    };
    load();
    const timer = window.setInterval(load, REFRESH_MS);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, [view]);

  return (
    <section>
      <header className="section-header">
        <h2>Incidents</h2>
        <div role="group" aria-label="Which incidents" className="views">
          {Object.keys(VIEWS).map((name) => (
            <button
              key={name}
              type="button"
              aria-pressed={view === name}
              onClick={() => setView(name)}
            >
              {name}
            </button>
          ))}
        </div>
      </header>
      {error !== null && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {items === null && error === null && <p>Loading…</p>}
      {items !== null && items.length === 0 && <p>No incidents.</p>}
      {items !== null && items.length > 0 && (
        <table className="incidents">
          <thead>
            <tr>
              <th scope="col">Number</th>
              <th scope="col">Severity</th>
              <th scope="col">State</th>
              <th scope="col">Title</th>
              <th scope="col">Target</th>
              <th scope="col">Direction</th>
              <th scope="col">Opened</th>
              <th scope="col">Assigned</th>
            </tr>
          </thead>
          <tbody>
            {items.map((incident) => (
              <tr key={incident.incident_id}>
                <td className="mono">{incident.incident_number}</td>
                <td>
                  <Severity value={incident.severity} />
                </td>
                <td>{incident.state}</td>
                <td>{incident.title}</td>
                <td className="mono">{incident.target_id}</td>
                <td>{incident.direction}</td>
                <td>
                  <time dateTime={incident.opened_at}>{incident.opened_at}</time>
                </td>
                <td>{incident.assigned_user_id ?? incident.assigned_team_id ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
