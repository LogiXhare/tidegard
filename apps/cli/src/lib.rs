//! `wetechinetmonctl`: the incident CLI (Milestone 5E, ADR 0040), with
//! mitigations, the kill switch and BGP since Phase 7E (ADR 0050).
//!
//! An API client and nothing more. Every command is one or two API
//! requests; the CLI holds no business logic and never touches the
//! database, so authorization and audit cannot be bypassed by using it.

pub mod args;
pub mod client;
pub mod config;
pub mod exit;
mod mitigations;
pub mod output;

use std::io::{BufRead, Write};

use hyper::Method;
use serde_json::{json, Value};
use wetechinetmon_common::rfc3339::{parse_rfc3339, rfc3339};

use crate::args::{is_uuid, Action, Command, IncidentRef, Invocation, OpenArgs, Output, Until};
use crate::client::{Call, Client, Reply};
use crate::config::Environment;

/// Where output goes, and what the terminal is.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// The operator's answers to confirmation prompts: `None` when stdin
    /// is not a terminal, so a prompt is an error rather than an assumed yes.
    pub input: Option<&'a mut dyn BufRead>,
    /// Microseconds since the epoch, for relative ages and `--for`.
    pub now_micros: i64,
}

/// Why a command stopped, already carrying its exit code.
#[derive(Debug)]
pub(crate) struct Stop {
    code: i32,
    /// For stderr; empty when the output already said it.
    message: String,
}

impl Stop {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Stop {
            code,
            message: message.into(),
        }
    }
}

/// Runs one command line and returns the exit code.
pub async fn run(args: &[String], env: &dyn Environment, io: &mut Io<'_>) -> i32 {
    run_with(args, env, io, |client| client).await
}

/// [`run`], with a hook to adjust the client (tests drop the backoff).
pub async fn run_with(
    args: &[String],
    env: &dyn Environment,
    io: &mut Io<'_>,
    adjust: impl FnOnce(Client) -> Client,
) -> i32 {
    let invocation = match args::parse(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            let _ = writeln!(io.err, "Error: {}\n\n{}", error.0, args::USAGE);
            return exit::USAGE;
        }
    };
    match invocation.command {
        Command::Help => {
            let _ = write!(io.out, "{}", args::USAGE);
            return exit::SUCCESS;
        }
        Command::Version => {
            let _ = writeln!(io.out, "wetechinetmonctl {}", env!("CARGO_PKG_VERSION"));
            return exit::SUCCESS;
        }
        _ => {}
    }
    let endpoint = match config::resolve(env, invocation.global.profile.as_deref()) {
        Ok(endpoint) => endpoint,
        Err(message) => {
            let _ = writeln!(io.err, "Error: {message}");
            return exit::USAGE;
        }
    };
    let client = match Client::new(endpoint) {
        Ok(client) => adjust(client),
        Err(error) => {
            let _ = writeln!(io.err, "Error: {error}");
            return exit::USAGE;
        }
    };
    match execute(&client, &invocation, io).await {
        Ok(()) => exit::SUCCESS,
        Err(stop) => {
            if !stop.message.is_empty() {
                let _ = write!(io.err, "{}", stop.message);
                if !stop.message.ends_with('\n') {
                    let _ = writeln!(io.err);
                }
            }
            stop.code
        }
    }
}

/// `value` with every byte outside the RFC 3986 unreserved set escaped.
pub fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub(crate) fn query_string(pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let joined: Vec<String> = pairs
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect();
    format!("?{}", joined.join("&"))
}

/// Sends `call`; a non-success answer stops the command with its exit
/// code, printing the problem document (verbatim under `--output json`).
pub(crate) async fn fetch(
    client: &Client,
    call: Call,
    io: &mut Io<'_>,
    output: Output,
) -> Result<Reply, Stop> {
    let reply = client
        .send(&call)
        .await
        .map_err(|error| Stop::new(exit::UNAVAILABLE, format!("Error: {error}")))?;
    if reply.status.is_success() {
        return Ok(reply);
    }
    let code = exit::for_status(reply.status);
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Err(Stop::new(code, ""));
    }
    let message = match serde_json::from_slice::<Value>(&reply.body) {
        Ok(document) => output::problem(&document),
        Err(_) => format!("Error: the API answered {}\n", reply.status),
    };
    Err(Stop::new(code, message))
}

pub(crate) fn get(path: String) -> Call {
    Call {
        method: Method::GET,
        path,
        body: None,
        idempotency_key: None,
    }
}

pub(crate) fn print_verbatim(io: &mut Io<'_>, body: &[u8]) {
    let _ = io.out.write_all(body);
    if !body.ends_with(b"\n") {
        let _ = writeln!(io.out);
    }
}

pub(crate) fn parse_json(body: &[u8]) -> Result<Value, Stop> {
    serde_json::from_slice(body).map_err(|_| {
        Stop::new(
            exit::FAILURE,
            "Error: the API answered with something other than JSON",
        )
    })
}

/// The incident's id: as given if it is one, else looked up by number in
/// the caller's tenant (ADR 0040).
pub(crate) async fn resolve_id(
    client: &Client,
    incident: &IncidentRef,
    io: &mut Io<'_>,
    output: Output,
) -> Result<String, Stop> {
    let text = incident.0.as_str();
    if is_uuid(text) {
        return Ok(text.to_ascii_lowercase());
    }
    let well_formed = !text.is_empty()
        && text.len() <= 32
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !well_formed {
        return Err(Stop::new(
            exit::USAGE,
            format!(
                "Error: {:?} is neither an incident id nor an incident number\n",
                output::clean(text)
            ),
        ));
    }
    let reply = fetch(
        client,
        get(format!(
            "/api/v1/incidents?incident_number={}&limit=1",
            encode(text)
        )),
        io,
        output,
    )
    .await?;
    let page = parse_json(&reply.body)?;
    page["items"][0]["incident_id"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| {
            Stop::new(
                exit::NOT_FOUND,
                format!("Error: no incident numbered {text}\n"),
            )
        })
}

async fn execute(client: &Client, invocation: &Invocation, io: &mut Io<'_>) -> Result<(), Stop> {
    let output = invocation.global.output;
    let wide = output == Output::Wide;
    match &invocation.command {
        Command::Help | Command::Version => Ok(()),
        Command::List(list) => {
            let reply = fetch(
                client,
                get(format!("/api/v1/incidents{}", query_string(&list.query))),
                io,
                output,
            )
            .await?;
            if output == Output::Json {
                print_verbatim(io, &reply.body);
                return Ok(());
            }
            let page = parse_json(&reply.body)?;
            let _ = write!(
                io.out,
                "{}",
                output::incident_list(&page, wide, io.now_micros)
            );
            if let Some(cursor) = page["next_cursor"].as_str() {
                let _ = writeln!(io.err, "More: add --cursor {cursor}");
            }
            Ok(())
        }
        Command::Show(incident) => {
            let id = resolve_id(client, incident, io, output).await?;
            let reply = fetch(client, get(format!("/api/v1/incidents/{id}")), io, output).await?;
            if output == Output::Json {
                print_verbatim(io, &reply.body);
                return Ok(());
            }
            let incident = parse_json(&reply.body)?;
            let _ = write!(io.out, "{}", output::incident(&incident, io.now_micros));
            Ok(())
        }
        Command::History {
            kind,
            incident,
            query,
        } => {
            let id = resolve_id(client, incident, io, output).await?;
            let path = format!(
                "/api/v1/incidents/{id}/{}{}",
                kind.path(),
                query_string(query)
            );
            let reply = fetch(client, get(path), io, output).await?;
            if output == Output::Json {
                print_verbatim(io, &reply.body);
                return Ok(());
            }
            let page = parse_json(&reply.body)?;
            let _ = write!(io.out, "{}", output::history(*kind, &page, wide));
            if let Some(cursor) = page["next_cursor"].as_str() {
                let _ = writeln!(io.err, "More: add --cursor {cursor}");
            }
            Ok(())
        }
        Command::NoteList(incident) => {
            let id = resolve_id(client, incident, io, output).await?;
            let reply = fetch(
                client,
                get(format!("/api/v1/incidents/{id}/notes")),
                io,
                output,
            )
            .await?;
            if output == Output::Json {
                print_verbatim(io, &reply.body);
                return Ok(());
            }
            let list = parse_json(&reply.body)?;
            let _ = write!(io.out, "{}", output::notes(&list));
            Ok(())
        }
        Command::Open(open) => open_incident(client, open, io, output).await,
        Command::Export { incident, file } => {
            export(client, incident, file.as_deref(), io, output).await
        }
        Command::Tag {
            incident,
            key,
            value,
        } => tag(client, incident, key, value.as_deref(), io, output).await,
        Command::Change {
            incident,
            action,
            expected_version,
            yes,
        } => {
            change(
                client,
                incident,
                action,
                *expected_version,
                *yes,
                io,
                output,
            )
            .await
        }
        Command::MitigationList { query } => mitigations::list(client, query, io, output).await,
        Command::MitigationShow(mitigation) => {
            mitigations::detail(client, mitigation, io, output).await
        }
        Command::MitigationHistory(mitigation) => {
            mitigations::history(client, mitigation, io, output).await
        }
        Command::MitigationRequest(request) => {
            mitigations::request(client, request, io, output).await
        }
        Command::MitigationChange {
            mitigation,
            action,
            expected_version,
            yes,
        } => {
            mitigations::change(
                client,
                mitigation,
                action,
                *expected_version,
                *yes,
                io,
                output,
            )
            .await
        }
        Command::KillSwitchStatus => mitigations::kill_switch_status(client, io, output).await,
        Command::KillSwitchEngage { reason, yes } => {
            mitigations::kill_switch_engage(client, reason, *yes, io, output).await
        }
        Command::BgpRoutes => mitigations::bgp_routes(client, io, output).await,
        Command::BgpPeers => mitigations::bgp_peers(client, io, output).await,
    }
}

/// One key per logical command: a UUIDv7, the same on every retry
/// (`Client::send` resends the same `Call`), so a retried change the
/// server already applied is replayed, never applied twice.
pub(crate) fn idempotency_key(now_micros: i64) -> String {
    let micros = u64::try_from(now_micros).unwrap_or(0);
    let timestamp = uuid::Timestamp::from_unix(
        uuid::NoContext,
        micros / 1_000_000,
        u32::try_from(micros % 1_000_000).unwrap_or(0) * 1_000,
    );
    format!("wnmctl-{}", uuid::Uuid::new_v7(timestamp))
}

const SEVERITIES: [&str; 4] = ["info", "minor", "major", "critical"];

/// The question to ask before `action`, if it needs one: closing,
/// reopening, suppressing, and lowering severity (the CLI plan).
fn confirmation(action: &Action, current: Option<&Value>, name: &str) -> Option<String> {
    let state = current
        .and_then(|incident| incident["state"].as_str())
        .map(|state| format!(", now {}", output::clean(state)))
        .unwrap_or_default();
    match action {
        Action::Close { reason, .. } => {
            Some(format!("Close {name}{state} as {}?", output::clean(reason)))
        }
        Action::Reopen { .. } => Some(format!("Reopen {name}{state}?")),
        Action::Suppress { .. } => Some(format!(
            "Suppress {name}{state}? Detections will not alert while it lasts."
        )),
        Action::NoteRedact { index, .. } => Some(format!(
            "Redact note #{index} on {name}? Its text is removed for good."
        )),
        Action::Severity { level, .. } => {
            let from = current.and_then(|incident| incident["severity"].as_str())?;
            let rank = |text: &str| SEVERITIES.iter().position(|s| *s == text);
            match (rank(from), rank(level)) {
                (Some(from_rank), Some(to_rank)) if to_rank < from_rank => Some(format!(
                    "Lower {name} from {from} to {}?",
                    output::clean(level)
                )),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Asks `question`; only `y` or `yes` proceeds. Without a terminal there
/// is no one to ask, and that is an error, never an assumed yes.
/// `command` names it in that error, such as `incidents close`.
pub(crate) fn confirm(io: &mut Io<'_>, question: &str, command: &str) -> Result<(), Stop> {
    let Some(input) = io.input.as_mut() else {
        return Err(Stop::new(
            exit::USAGE,
            format!(
                "Error: {command} asks for confirmation, and there is no terminal \
                 to ask. Pass --yes to confirm in advance.\n"
            ),
        ));
    };
    let _ = write!(io.err, "{question} [y/N] ");
    let _ = io.err.flush();
    let mut answer = String::new();
    let _ = input.read_line(&mut answer);
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err(Stop::new(exit::FAILURE, "Aborted; nothing was changed.\n")),
    }
}

/// The JSON body the API action takes.
fn body(action: &Action, version: Option<u64>, now_micros: i64) -> Result<Value, Stop> {
    let mut body = match action {
        Action::Acknowledge
        | Action::Investigate
        | Action::Monitor
        | Action::Unassign
        | Action::Unsuppress => json!({}),
        Action::Resolve { note } => json!({ "resolution_note": note }),
        Action::Close { reason, detail } => json!({ "closure_reason": reason, "detail": detail }),
        Action::Reopen { reason } => json!({ "reason": reason }),
        Action::Suppress { until, reason } => {
            let expires_at = match until {
                Until::At(text) => {
                    parse_rfc3339(text).ok_or_else(|| {
                        Stop::new(
                            exit::USAGE,
                            format!(
                                "Error: --until {:?} is not RFC 3339 UTC, such as \
                                 2026-10-06T02:00:00Z\n",
                                output::clean(text)
                            ),
                        )
                    })?;
                    text.clone()
                }
                Until::For(duration) => {
                    let micros = i64::try_from(duration.as_micros()).unwrap_or(i64::MAX);
                    rfc3339(now_micros.saturating_add(micros))
                }
            };
            json!({ "reason": reason, "expires_at": expires_at })
        }
        Action::AssignUser(user) => json!({ "user_id": user }),
        Action::AssignTeam(team) => json!({ "team_id": team }),
        // Resolved to AssignUser before a body is built.
        Action::Claim => {
            return Err(Stop::new(
                exit::FAILURE,
                "Error: claim was not resolved to a user
",
            ))
        }
        Action::Severity { level, reason } => json!({ "severity": level, "reason": reason }),
        Action::Priority { level } => json!({ "priority": level }),
        Action::Note { body } | Action::NoteEdit { body, .. } => json!({ "body": body }),
        Action::NoteRedact { reason, .. } => json!({ "reason": reason }),
    };
    let object = body.as_object_mut().expect("every body is an object");
    // Optional fields the operator left out are omitted, not sent as null.
    object.retain(|_, value| !value.is_null());
    if let Some(version) = version {
        object.insert("expected_version".into(), version.into());
    }
    Ok(body)
}

/// One change: resolve, read the version (unless pinned), confirm where
/// the plan asks, then one request with one idempotency key, reused by
/// every retry.
async fn change(
    client: &Client,
    incident: &IncidentRef,
    action: &Action,
    expected_version: Option<u64>,
    yes: bool,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let id = resolve_id(client, incident, io, output).await?;
    let claimed;
    let action = if matches!(action, Action::Claim) {
        claimed = Action::AssignUser(caller(client, io, output).await?);
        &claimed
    } else {
        action
    };
    let needs_current = (action.is_versioned() && expected_version.is_none())
        || matches!(action, Action::Severity { .. });
    let current = if needs_current {
        let reply = fetch(client, get(format!("/api/v1/incidents/{id}")), io, output).await?;
        Some(parse_json(&reply.body)?)
    } else {
        None
    };
    let version = if action.is_versioned() {
        Some(
            expected_version
                .or_else(|| current.as_ref().and_then(|c| c["version"].as_u64()))
                .ok_or_else(|| Stop::new(exit::FAILURE, "Error: the incident has no version\n"))?,
        )
    } else {
        None
    };
    let name = current
        .as_ref()
        .and_then(|c| c["incident_number"].as_str())
        .map(output::clean)
        .unwrap_or_else(|| output::clean(&incident.0));
    let verb = action.verb();
    if let Some(question) = confirmation(action, current.as_ref(), &name) {
        if !yes {
            confirm(io, &question, &format!("incidents {verb}"))?;
        }
    }
    let call = Call {
        method: Method::POST,
        path: format!("/api/v1/incidents/{id}/{}", action.path()),
        body: Some(
            body(action, version, io.now_micros)?
                .to_string()
                .into_bytes(),
        ),
        idempotency_key: Some(idempotency_key(io.now_micros)),
    };
    let reply = match fetch(client, call, io, output).await {
        Ok(reply) => reply,
        Err(mut stop) => {
            if stop.code == exit::CONFLICT && output != Output::Json {
                stop.message.push_str(&format!(
                    "\nRe-read the incident and decide again:\n  wetechinetmonctl incidents show {}\n",
                    output::clean(&incident.0)
                ));
            }
            return Err(stop);
        }
    };
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Ok(());
    }
    let after = parse_json(&reply.body)?;
    let _ = writeln!(
        io.out,
        "{}: {} done; state {}, version {}",
        field_or(&after, "incident_number", &name),
        verb,
        field_or(&after, "state", "?"),
        field_or(&after, "version", "?"),
    );
    Ok(())
}

pub(crate) fn field_or(value: &Value, name: &str, fallback: &str) -> String {
    match &value[name] {
        Value::String(text) => output::clean(text),
        Value::Null => output::clean(fallback),
        other => other.to_string(),
    }
}

/// The caller's operator id, from `GET /whoami`, for `claim`.
async fn caller(client: &Client, io: &mut Io<'_>, output: Output) -> Result<String, Stop> {
    let reply = fetch(client, get("/api/v1/whoami".to_string()), io, output).await?;
    let me = parse_json(&reply.body)?;
    match (me["actor_type"].as_str(), me["actor_id"].as_str()) {
        (Some("operator"), Some(id)) if !id.is_empty() => Ok(id.to_string()),
        _ => Err(Stop::new(
            exit::USAGE,
            "Error: claim assigns to the operator the token belongs to, and this token \
             is not an operator's. Use incidents assign --user instead.\n",
        )),
    }
}

/// `incidents open`: `POST /api/v1/incidents` with one idempotency key.
async fn open_incident(
    client: &Client,
    open: &OpenArgs,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let mut body = json!({
        "title": open.title,
        "description": open.description,
        "severity": open.severity,
        "priority": open.priority,
        "target_scope": open.target_scope,
        "target": open.target,
        "direction": open.direction,
        "address_family": open.address_family,
    });
    body.as_object_mut()
        .expect("an object")
        .retain(|_, value| !value.is_null());
    let call = Call {
        method: Method::POST,
        path: "/api/v1/incidents".to_string(),
        body: Some(body.to_string().into_bytes()),
        idempotency_key: Some(idempotency_key(io.now_micros)),
    };
    let reply = fetch(client, call, io, output).await?;
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Ok(());
    }
    let opened = parse_json(&reply.body)?;
    let _ = writeln!(
        io.out,
        "Opened {} ({})",
        field_or(&opened, "incident_number", "?"),
        field_or(&opened, "incident_id", "?"),
    );
    Ok(())
}

/// `incidents export`: the API's document, verbatim, to a new file or
/// stdout. An existing file is never overwritten.
async fn export(
    client: &Client,
    incident: &IncidentRef,
    file: Option<&str>,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let id = resolve_id(client, incident, io, output).await?;
    let call = Call {
        method: Method::POST,
        path: format!("/api/v1/incidents/{id}/export"),
        body: None,
        idempotency_key: None,
    };
    let reply = fetch(client, call, io, output).await?;
    let Some(path) = file else {
        print_verbatim(io, &reply.body);
        return Ok(());
    };
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut handle| handle.write_all(&reply.body));
    match written {
        Ok(()) => {
            let _ = writeln!(io.err, "Exported to {path}");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(Stop::new(
            exit::USAGE,
            format!("Error: {path} exists; an export never overwrites a file\n"),
        )),
        Err(error) => Err(Stop::new(
            exit::FAILURE,
            format!("Error: {path}: {error}\n"),
        )),
    }
}

/// `incidents tag set|remove`: `PUT` or `DELETE` one tag.
async fn tag(
    client: &Client,
    incident: &IncidentRef,
    key: &str,
    value: Option<&str>,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let id = resolve_id(client, incident, io, output).await?;
    let path = format!("/api/v1/incidents/{id}/tags/{}", encode(key));
    let call = match value {
        Some(value) => Call {
            method: Method::PUT,
            path,
            body: Some(json!({ "value": value }).to_string().into_bytes()),
            idempotency_key: Some(idempotency_key(io.now_micros)),
        },
        None => Call {
            method: Method::DELETE,
            path,
            body: None,
            idempotency_key: Some(idempotency_key(io.now_micros)),
        },
    };
    let reply = fetch(client, call, io, output).await?;
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Ok(());
    }
    let after = parse_json(&reply.body)?;
    let _ = writeln!(
        io.out,
        "{}: tag {} {}; version {}",
        field_or(&after, "incident_number", &incident.0),
        output::clean(key),
        if value.is_some() { "set" } else { "removed" },
        field_or(&after, "version", "?"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_are_escaped() {
        assert_eq!(encode("WNM-2026-000123"), "WNM-2026-000123");
        assert_eq!(encode("a&b=c d"), "a%26b%3Dc%20d");
        assert_eq!(
            query_string(&[
                ("state".into(), "open".into()),
                ("cursor".into(), "x/y".into())
            ]),
            "?state=open&cursor=x%2Fy"
        );
    }

    #[test]
    fn ids_are_told_from_numbers() {
        assert!(is_uuid("0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d"));
        assert!(!is_uuid("WNM-2026-000123"));
        assert!(!is_uuid("0192f3c4x8a7b-7e1f-9c2d-3e4f5a6b7c8d"));
    }
}
