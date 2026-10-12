// One incident: its facts, the actions the operator may take now, its
// notes and its timeline. Every action sends the version the operator saw;
// if someone else changed the incident first, the API refuses and the page
// reloads instead of guessing (ADR 0016). Untrusted text is only text (T-08).
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import {
  addNote,
  ApiError,
  editNote,
  getIncident,
  getNotes,
  getTimeline,
  redactNote,
  transition,
  whoAmI,
} from "../api";
import type { Incident, Note, TimelineEntry, WhoAmI } from "../api";
import { ReasonControl } from "../components/ReasonControl";
import { Severity } from "../components/Severity";

/** Operator moves the state machine allows, from each state. */
const MOVES: Record<string, { action: string; label: string; to: string }[]> = {
  open: [
    { action: "acknowledge", label: "Acknowledge", to: "acknowledged" },
    { action: "investigate", label: "Investigate", to: "investigating" },
  ],
  acknowledged: [
    { action: "investigate", label: "Investigate", to: "investigating" },
    { action: "monitor", label: "Monitor", to: "monitoring" },
  ],
  investigating: [{ action: "monitor", label: "Monitor", to: "monitoring" }],
  monitoring: [{ action: "investigate", label: "Investigate again", to: "investigating" }],
  recovering: [],
  resolved: [],
  closed: [],
};
const RESOLVABLE = ["open", "acknowledged", "investigating", "monitoring", "recovering"];
const SEVERITIES = ["info", "minor", "major", "critical"];
const CLOSURE_REASONS = [
  "resolved",
  "false_positive",
  "duplicate",
  "expected_traffic",
  "no_action_required",
  "other",
];

/** Prefills the mitigation form with the attacked host and this incident. */
function mitigateQuery(incident: Incident): string {
  const length = incident.target_id.includes(":") ? 128 : 32;
  return new URLSearchParams({
    incident: incident.incident_id,
    prefix: `${incident.target_id}/${length}`,
  }).toString();
}

function describe(failure: unknown): string {
  if (failure instanceof ApiError) {
    if (failure.problem.error === "incident.version_conflict") {
      return "Someone else changed this incident first. It has been reloaded: look again before acting.";
    }
    return failure.problem.detail ?? failure.problem.title;
  }
  return "The API could not be reached.";
}

export function IncidentDetail() {
  const { incidentId = "" } = useParams();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  /** Bumped after every change, so the page reloads what happened. */
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let live = true;
    Promise.all([getIncident(incidentId), getNotes(incidentId), getTimeline(incidentId)])
      .then(([found, foundNotes, foundTimeline]) => {
        if (!live) return;
        setIncident(found);
        setNotes(foundNotes);
        setTimeline(foundTimeline);
      })
      .catch((failure: unknown) => {
        if (live) setError(describe(failure));
      });
    return () => {
      live = false;
    };
  }, [incidentId, revision]);

  useEffect(() => {
    let live = true;
    whoAmI()
      .then((found) => {
        if (live) setMe(found);
      })
      .catch(() => {
        if (live) setMe(null);
      });
    return () => {
      live = false;
    };
  }, []);

  const can = (permission: string) => me?.permissions.includes(permission) ?? false;

  /** Runs one change, then reloads whatever happened. */
  async function act(change: () => Promise<unknown>, question?: string) {
    if (question !== undefined && !window.confirm(question)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await change();
    } catch (failure) {
      setError(describe(failure));
    } finally {
      setRevision((current) => current + 1);
      setBusy(false);
    }
  }

  if (incident === null) {
    return error === null ? <p>Loading…</p> : <p role="alert" className="error">{error}</p>;
  }
  const version = incident.version;
  const id = incident.incident_id;

  return (
    <article className="incident">
      <p>
        <Link to="/incidents">← Incidents</Link>
      </p>
      <header>
        <h2>
          <span className="mono">{incident.incident_number}</span> {incident.title}
        </h2>
        <p className="facts">
          <Severity value={incident.severity} /> · <span>{incident.state}</span> ·{" "}
          <span>{incident.priority}</span> · <span className="mono">{incident.target_id}</span>{" "}
          · <span>{incident.direction}</span>
        </p>
        {incident.description !== null && <p>{incident.description}</p>}
        <p className="safety">
          Mitigation: <strong>{incident.mitigation_status}</strong> · Notification:{" "}
          <strong>{incident.notification_status}</strong>
          {can("mitigation.request") && incident.target_type === "host" && (
            <>
              {" "}
              ·{" "}
              <Link to={`/mitigations?${mitigateQuery(incident)}`}>Request a mitigation</Link>
            </>
          )}
        </p>
      </header>

      {error !== null && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <section aria-label="Actions" className="actions">
        {(MOVES[incident.state] ?? []).map((move) =>
          can(move.action === "acknowledge" ? "incident.acknowledge" : "incident.investigate") ? (
            <button
              key={move.action}
              type="button"
              disabled={busy}
              onClick={() => void act(() => transition(id, move.action, version))}
            >
              {move.label}
            </button>
          ) : null,
        )}
        {RESOLVABLE.includes(incident.state) && can("incident.resolve") && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void act(() => transition(id, "resolve", version))}
          >
            Resolve
          </button>
        )}
        {incident.state === "resolved" && can("incident.close") && (
          <CloseControl
            busy={busy}
            onClose={(reason) =>
              void act(
                () => transition(id, "close", version, { closure_reason: reason }),
                `Close ${incident.incident_number} as ${reason}?`,
              )
            }
          />
        )}
        {(incident.state === "resolved" || incident.state === "closed") && can("incident.reopen") && (
          <ReasonControl
            label="Reopen"
            busy={busy}
            onSubmit={(reason) =>
              void act(
                () => transition(id, "reopen", version, { reason }),
                `Reopen ${incident.incident_number}?`,
              )
            }
          />
        )}
        {can("incident.assign") && me !== null && incident.assigned_user_id !== me.actor_id && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void act(() => transition(id, "assign", version, { user_id: me.actor_id }))}
          >
            Assign to me
          </button>
        )}
        {can("incident.assign") &&
          (incident.assigned_user_id !== null || incident.assigned_team_id !== null) && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void act(() => transition(id, "unassign", version))}
            >
              Unassign
            </button>
          )}
        {can("incident.severity.change") && (
          <SeverityControl
            current={incident.severity}
            busy={busy}
            onChange={(severity, reason) => {
              const lowering = SEVERITIES.indexOf(severity) < SEVERITIES.indexOf(incident.severity);
              void act(
                () =>
                  transition(id, "severity", version, {
                    severity,
                    ...(reason === "" ? {} : { reason }),
                  }),
                lowering ? `Lower ${incident.incident_number} from ${incident.severity} to ${severity}?` : undefined,
              );
            }}
          />
        )}
      </section>

      <section aria-label="Notes" className="notes">
        <h3>Notes</h3>
        {notes.length === 0 && <p>No notes.</p>}
        <ol>
          {notes.map((note) => (
            <li key={note.note_index}>
              <p className="meta">
                #{note.note_index} by <span>{note.author}</span>
                {note.supersedes_note_index !== null && <> · edits #{note.supersedes_note_index}</>}
                {note.redacted && <> · redacted</>}
              </p>
              {note.redacted ? <p className="muted">This note was redacted.</p> : <p className="body">{note.body}</p>}
              {!note.redacted && me !== null && note.author === me.actor_id && can("incident.note.create") && (
                <ReasonControl
                  label="Edit"
                  busy={busy}
                  initial={note.body}
                  onSubmit={(body) => void act(() => editNote(id, note.note_index, body))}
                />
              )}
              {!note.redacted && can("incident.note.redact") && (
                <ReasonControl
                  label="Redact"
                  busy={busy}
                  onSubmit={(reason) =>
                    void act(
                      () => redactNote(id, note.note_index, reason),
                      `Redact note #${note.note_index}? Its text is removed for good.`,
                    )
                  }
                />
              )}
            </li>
          ))}
        </ol>
        {can("incident.note.create") && (
          <ReasonControl label="Add note" busy={busy} onSubmit={(body) => void act(() => addNote(id, body))} />
        )}
      </section>

      <section aria-label="Timeline" className="timeline">
        <h3>Timeline</h3>
        <ol>
          {timeline.map((entry) => (
            <li key={entry.timeline_id}>
              <time dateTime={entry.occurred_at}>{entry.occurred_at}</time> ·{" "}
              <span>{entry.entry_type}</span> · <span>{entry.actor}</span>
            </li>
          ))}
        </ol>
      </section>
    </article>
  );
}

function CloseControl({ busy, onClose }: { busy: boolean; onClose: (reason: string) => void }) {
  const [reason, setReason] = useState("resolved");
  return (
    <form
      className="inline"
      onSubmit={(event) => {
        event.preventDefault();
        onClose(reason);
      }}
    >
      <select aria-label="Closure reason" value={reason} onChange={(event) => setReason(event.target.value)}>
        {CLOSURE_REASONS.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>
      <button type="submit" disabled={busy}>
        Close
      </button>
    </form>
  );
}

function SeverityControl({
  current,
  busy,
  onChange,
}: {
  current: string;
  busy: boolean;
  onChange: (severity: string, reason: string) => void;
}) {
  const [severity, setSeverity] = useState(current);
  const [reason, setReason] = useState("");
  return (
    <form
      className="inline"
      onSubmit={(event) => {
        event.preventDefault();
        onChange(severity, reason.trim());
      }}
    >
      <select aria-label="Severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
        {SEVERITIES.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>
      <input aria-label="Reason" placeholder="reason" value={reason} onChange={(event) => setReason(event.target.value)} />
      <button type="submit" disabled={busy || severity === current}>
        Change severity
      </button>
    </form>
  );
}
