// The NOC overview: what is happening now. Active incidents by severity,
// traffic over the last hour, the top hosts, and any exporter gone silent.
// Traffic is shown only to the traffic tenant (ADR 0042); anyone else sees
// incidents alone.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { exporters, listIncidents, topHosts, trafficSummary } from "../api";
import type { Exporter, IncidentSummary, TopEntry, TrafficSummary } from "../api";
import { bitsPerSecond, RateChart } from "../components/RateChart";
import { Severity } from "../components/Severity";

const ACTIVE = ["open", "acknowledged", "investigating", "monitoring", "recovering"];
const SEVERITIES = ["critical", "major", "minor", "info"];
const REFRESH_MS = 30_000;
/** An exporter quiet for longer than this is called out. */
export const SILENT_AFTER_SECONDS = 300;

interface Snapshot {
  incidents: IncidentSummary[];
  traffic: TrafficSummary | null;
  hosts: TopEntry[] | null;
  exporters: Exporter[] | null;
}

export function Overview() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () => {
      Promise.all([listIncidents(ACTIVE), trafficSummary(), topHosts(10), exporters()])
        .then(([page, traffic, hosts, found]) => {
          if (!live) return;
          setSnapshot({ incidents: page.items, traffic, hosts, exporters: found });
          setError(null);
        })
        .catch(() => {
          if (live) setError("The API could not be reached. Showing the last data received.");
        });
    };
    load();
    const timer = window.setInterval(load, REFRESH_MS);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, []);

  if (snapshot === null) {
    return error === null ? <p>Loading…</p> : <p role="alert" className="error">{error}</p>;
  }
  const counts = SEVERITIES.map((severity) => ({
    severity,
    count: snapshot.incidents.filter((incident) => incident.severity === severity).length,
  }));
  const silent = (snapshot.exporters ?? []).filter(
    (exporter) => exporter.silent_seconds > SILENT_AFTER_SECONDS,
  );
  const latest = snapshot.traffic?.points.at(-1);

  return (
    <section className="overview">
      <h2>Overview</h2>
      {error !== null && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <ul className="tiles" aria-label="Active incidents by severity">
        {counts.map(({ severity, count }) => (
          <li key={severity} className="tile">
            <Severity value={severity} />
            <strong>{count}</strong>
            <span className="muted">active</span>
          </li>
        ))}
        {latest !== undefined && (
          <li className="tile">
            <span>Traffic now</span>
            <strong>{bitsPerSecond(latest.ipv4_bps + latest.ipv6_bps)}</strong>
          </li>
        )}
        {snapshot.exporters !== null && (
          <li className="tile">
            <span>Silent exporters</span>
            <strong>{silent.length}</strong>
            <span className="muted">of {snapshot.exporters.length}</span>
          </li>
        )}
      </ul>

      <h3>Active incidents</h3>
      {snapshot.incidents.length === 0 ? (
        <p>No active incidents.</p>
      ) : (
        <ul className="plain">
          {snapshot.incidents.slice(0, 10).map((incident) => (
            <li key={incident.incident_id}>
              <Severity value={incident.severity} />{" "}
              <Link to={`/incidents/${encodeURIComponent(incident.incident_id)}`}>
                {incident.incident_number}
              </Link>{" "}
              <span>{incident.title}</span> · <span className="mono">{incident.target_id}</span> ·{" "}
              <span>{incident.state}</span>
            </li>
          ))}
        </ul>
      )}

      {snapshot.traffic === null ? (
        <p className="muted">Traffic is not available to this tenant.</p>
      ) : (
        <>
          <h3>Traffic, last hour</h3>
          <RateChart points={snapshot.traffic.points} />
        </>
      )}

      {snapshot.hosts !== null && (
        <>
          <h3>Top hosts, last hour</h3>
          <table className="incidents">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Bytes</th>
                <th scope="col">Packets</th>
                <th scope="col">Flows</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.hosts.map((host) => (
                <tr key={host.key}>
                  <td className="mono">{host.key}</td>
                  <td>{host.bytes.toLocaleString()}</td>
                  <td>{host.packets.toLocaleString()}</td>
                  <td>{host.flows.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {snapshot.exporters !== null && (
        <>
          <h3>Exporters</h3>
          <table className="incidents">
            <thead>
              <tr>
                <th scope="col">Exporter</th>
                <th scope="col">Status</th>
                <th scope="col">Last seen</th>
                <th scope="col">Rate, last 5 min</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.exporters.map((exporter) => {
                const quiet = exporter.silent_seconds > SILENT_AFTER_SECONDS;
                return (
                  <tr key={exporter.exporter}>
                    <td className="mono">{exporter.exporter}</td>
                    <td className={quiet ? "warn" : undefined}>
                      {quiet ? `⚠ silent ${Math.round(exporter.silent_seconds / 60)} min` : "✓ reporting"}
                    </td>
                    <td>
                      <time dateTime={exporter.last_seen}>{exporter.last_seen}</time>
                    </td>
                    <td>{bitsPerSecond(exporter.bps)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
