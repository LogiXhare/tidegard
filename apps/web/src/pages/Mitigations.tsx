// BGP mitigations (ADR 0050): request, approve, reject and withdraw, the
// kill switch, and GoBGP's peers. The page only asks the API; the mitigator
// announces. Every decision sends the version the operator saw, and the ones
// that change what is announced ask first. Untrusted text is only text (T-08).
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import {
  ApiError,
  bgpPeers,
  decideMitigation,
  engageKillSwitch,
  getKillSwitch,
  listMitigations,
  requestMitigation,
  whoAmI,
} from "../api";
import type { BgpPeer, FlowMatch, KillSwitch, Mitigation, MitigationRequest, WhoAmI } from "../api";
import { ReasonControl } from "../components/ReasonControl";

const ACTIONS = ["rtbh", "parent_prefix", "flowspec_discard", "flowspec_rate_limit"];
const AWAITING = ["proposed", "requested"];
const WITHDRAWABLE = ["approved", "announcing", "active"];
/** The mitigator moves things along every couple of seconds. */
const REFRESH_MS = 5_000;
/** Older than this, a peer snapshot means the mitigator has stopped. */
const STALE_PEERS_MS = 5 * 60_000;

function describe(failure: unknown): string {
  if (failure instanceof ApiError) {
    if (failure.problem.error === "mitigation.version_conflict") {
      return "Someone else changed this mitigation first. It has been reloaded: look again before acting.";
    }
    return failure.problem.detail ?? failure.problem.title;
  }
  return "The API could not be reached.";
}

export function Mitigations() {
  const [params] = useSearchParams();
  const [live, setLive] = useState(true);
  const [items, setItems] = useState<Mitigation[] | null>(null);
  const [killSwitch, setKillSwitch] = useState<KillSwitch | null>(null);
  const [peers, setPeers] = useState<BgpPeer[] | null>(null);
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Why the last refresh failed; cleared by the next one that works. */
  const [loadError, setLoadError] = useState<string | null>(null);
  /** When the peers were read, to judge how old their snapshot is. */
  const [readAt, setReadAt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let alive = true;
    whoAmI()
      .then((found) => {
        if (alive) setMe(found);
      })
      .catch(() => {
        if (alive) setMe(null);
      });
    return () => {
      alive = false;
    };
  }, []);

  const can = (permission: string) => me?.permissions.includes(permission) ?? false;
  const seesPeers = can("mitigation.kill_switch.engage");

  useEffect(() => {
    let alive = true;
    const load = () => {
      Promise.all([
        listMitigations(live),
        getKillSwitch(),
        seesPeers ? bgpPeers() : Promise.resolve(null),
      ])
        .then(([found, switchState, foundPeers]) => {
          if (!alive) return;
          setItems(found);
          setKillSwitch(switchState);
          setPeers(foundPeers);
          setReadAt(Date.now());
          setLoadError(null);
        })
        .catch((failure: unknown) => {
          if (alive) setLoadError(describe(failure));
        });
    };
    load();
    const timer = window.setInterval(load, REFRESH_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [live, seesPeers, revision]);

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

  return (
    <section className="mitigations">
      <header className="section-header">
        <h2>Mitigations</h2>
        <div role="group" aria-label="Which mitigations" className="views">
          <button type="button" aria-pressed={live} onClick={() => setLive(true)}>
            live
          </button>
          <button type="button" aria-pressed={!live} onClick={() => setLive(false)}>
            all
          </button>
        </div>
      </header>

      {killSwitch !== null && (
        <section aria-label="Kill switch" className={killSwitch.engaged ? "kill-switch engaged" : "kill-switch"}>
          {killSwitch.engaged ? (
            <p role="status">
              <strong>Kill switch engaged</strong>: nothing is announced, and live mitigations are withdrawn.
              {killSwitch.changed_by !== null && (
                <>
                  {" "}
                  By <span>{killSwitch.changed_by}</span>: <span>{killSwitch.reason}</span>.
                </>
              )}{" "}
              Only the API host can release it.
            </p>
          ) : (
            <p>Kill switch released.</p>
          )}
          {!killSwitch.engaged && can("mitigation.kill_switch.engage") && (
            <ReasonControl
              label="Engage kill switch"
              busy={busy}
              onSubmit={(reason) =>
                void act(
                  () => engageKillSwitch(reason),
                  "Engage the kill switch? Every live mitigation is withdrawn, nothing new is announced, and only the API host can release it.",
                )
              }
            />
          )}
        </section>
      )}

      {(error ?? loadError) !== null && (
        <p role="alert" className="error">
          {error ?? loadError}
        </p>
      )}

      {can("mitigation.request") && (
        <RequestForm
          busy={busy}
          initialPrefix={params.get("prefix") ?? ""}
          incidentId={params.get("incident")}
          onRequest={(body) => void act(() => requestMitigation(body))}
        />
      )}

      {items === null && loadError === null && <p>Loading…</p>}
      {items !== null && items.length === 0 && <p>No mitigations.</p>}
      {items !== null && items.length > 0 && (
        <table className="mitigation-list">
          <thead>
            <tr>
              <th scope="col">State</th>
              <th scope="col">Action</th>
              <th scope="col">Prefix</th>
              <th scope="col">Reason</th>
              <th scope="col">Requested by</th>
              <th scope="col">Approved by</th>
              <th scope="col">Expires</th>
              <th scope="col">Decide</th>
            </tr>
          </thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.mitigation_id} data-mitigation={m.mitigation_id}>
                <td>
                  <span className="state">{m.state}</span>
                  {m.dry_run === true && <span className="muted"> (dry-run)</span>}
                  {m.last_error !== null && <span className="muted"> · {m.last_error}</span>}
                </td>
                <td>{m.action}</td>
                <td className="mono">{m.prefix}</td>
                <td>
                  {m.reason}
                  {m.incident_id !== null && (
                    <>
                      {" "}
                      (<Link to={`/incidents/${encodeURIComponent(m.incident_id)}`}>incident</Link>)
                    </>
                  )}
                </td>
                <td>{m.requested_by}</td>
                <td>{m.approved_by ?? "—"}</td>
                <td>{m.expires_at === null ? "—" : <time dateTime={m.expires_at}>{m.expires_at}</time>}</td>
                <td className="decide">
                  {AWAITING.includes(m.state) && can("mitigation.approve") && (
                    <>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void act(
                            () => decideMitigation(m.mitigation_id, "approve", m.version),
                            `Approve ${m.action} of ${m.prefix}, requested by ${m.requested_by}? The mitigator will announce it to BGP unless the deployment is in dry-run.`,
                          )
                        }
                      >
                        Approve
                      </button>
                      <ReasonControl
                        label="Reject"
                        busy={busy}
                        onSubmit={(reason) =>
                          void act(() => decideMitigation(m.mitigation_id, "reject", m.version, reason))
                        }
                      />
                    </>
                  )}
                  {WITHDRAWABLE.includes(m.state) && can("mitigation.withdraw") && (
                    <ReasonControl
                      label="Withdraw"
                      busy={busy}
                      onSubmit={(reason) =>
                        void act(
                          () => decideMitigation(m.mitigation_id, "withdraw", m.version, reason),
                          `Withdraw ${m.action} of ${m.prefix}? Its route is taken down and the traffic it held back returns.`,
                        )
                      }
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {peers !== null && <Peers peers={peers} readAt={readAt} />}
    </section>
  );
}

function Peers({ peers, readAt }: { peers: BgpPeer[]; readAt: number }) {
  const newest = Math.max(...peers.map((peer) => Date.parse(peer.updated_at)));
  return (
    <section aria-label="BGP peers" className="peers">
      <h3>BGP peers</h3>
      {peers.length === 0 && <p>The mitigator reports no BGP peers.</p>}
      {peers.length > 0 && readAt - newest > STALE_PEERS_MS && (
        <p role="alert" className="error">
          The mitigator last reported its peers at {new Date(newest).toISOString()}. It may have stopped: these
          sessions may no longer be as shown.
        </p>
      )}
      {peers.length > 0 && (
        <table>
          <thead>
            <tr>
              <th scope="col">Neighbor</th>
              <th scope="col">ASN</th>
              <th scope="col">Session</th>
              <th scope="col">Seen</th>
            </tr>
          </thead>
          <tbody>
            {peers.map((peer) => (
              <tr key={peer.neighbor_address}>
                <td className="mono">{peer.neighbor_address}</td>
                <td>{peer.peer_asn}</td>
                <td>{peer.session_state}</td>
                <td>
                  <time dateTime={peer.updated_at}>{peer.updated_at}</time>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/** Optional whole numbers: empty is absent. */
function whole(text: string): number | undefined {
  return text.trim() === "" ? undefined : Number(text);
}

function RequestForm({
  busy,
  initialPrefix,
  incidentId,
  onRequest,
}: {
  busy: boolean;
  initialPrefix: string;
  incidentId: string | null;
  onRequest: (body: MitigationRequest) => void;
}) {
  const [prefix, setPrefix] = useState(initialPrefix);
  const [action, setAction] = useState("rtbh");
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState("30");
  const [protocol, setProtocol] = useState("");
  const [destinationPort, setDestinationPort] = useState("");
  const [source, setSource] = useState("");
  const [sourcePort, setSourcePort] = useState("");
  const [rate, setRate] = useState("");
  const flowspec = action.startsWith("flowspec_");
  const ready = prefix.trim() !== "" && reason.trim() !== "" && Number(minutes) > 0;

  return (
    <form
      aria-label="Request a mitigation"
      className="request"
      onSubmit={(event) => {
        event.preventDefault();
        const flow: FlowMatch = {};
        const numbers = [
          ["protocol", protocol],
          ["destination_port", destinationPort],
          ["source_port", sourcePort],
        ] as const;
        for (const [name, text] of numbers) {
          const value = whole(text);
          if (value !== undefined) flow[name] = value;
        }
        if (source.trim() !== "") flow.source = source.trim();
        const body: MitigationRequest = {
          prefix: prefix.trim(),
          action,
          reason: reason.trim(),
          duration_seconds: Math.round(Number(minutes) * 60),
        };
        if (incidentId !== null) body.incident_id = incidentId;
        if (flowspec && Object.keys(flow).length > 0) body.flow = flow;
        const bytesPerSecond = whole(rate);
        if (action === "flowspec_rate_limit" && bytesPerSecond !== undefined) {
          body.bytes_per_second = bytesPerSecond;
        }
        onRequest(body);
        setReason("");
      }}
    >
      <h3>Request a mitigation</h3>
      <p className="muted">
        A request announces nothing: a NOC lead approves it, then the mitigator announces it.
        {incidentId !== null && <> For incident <span className="mono">{incidentId}</span>.</>}
      </p>
      <label>
        Prefix <input aria-label="Prefix" value={prefix} onChange={(event) => setPrefix(event.target.value)} />
      </label>
      <label>
        Action{" "}
        <select aria-label="Action" value={action} onChange={(event) => setAction(event.target.value)}>
          {ACTIONS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      <label>
        Minutes{" "}
        <input
          aria-label="Minutes"
          type="number"
          min={1}
          value={minutes}
          onChange={(event) => setMinutes(event.target.value)}
        />
      </label>
      <label>
        Reason{" "}
        <input aria-label="Request reason" value={reason} maxLength={1000} onChange={(event) => setReason(event.target.value)} />
      </label>
      {flowspec && (
        <fieldset>
          <legend>FlowSpec match</legend>
          <label>
            Protocol <input aria-label="Protocol" type="number" min={0} max={255} value={protocol} onChange={(event) => setProtocol(event.target.value)} />
          </label>
          <label>
            Destination port{" "}
            <input aria-label="Destination port" type="number" min={0} max={65535} value={destinationPort} onChange={(event) => setDestinationPort(event.target.value)} />
          </label>
          <label>
            Source <input aria-label="Source prefix" value={source} onChange={(event) => setSource(event.target.value)} />
          </label>
          <label>
            Source port{" "}
            <input aria-label="Source port" type="number" min={0} max={65535} value={sourcePort} onChange={(event) => setSourcePort(event.target.value)} />
          </label>
          {action === "flowspec_rate_limit" && (
            <label>
              Bytes per second{" "}
              <input aria-label="Bytes per second" type="number" min={0} value={rate} onChange={(event) => setRate(event.target.value)} />
            </label>
          )}
        </fieldset>
      )}
      <button type="submit" disabled={busy || !ready}>
        Request
      </button>
    </form>
  );
}
