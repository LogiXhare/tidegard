//! `mitigations`, `kill-switch` and `bgp` (Phase 7E, ADR 0050).
//!
//! Like every other command, an API client and nothing more: the API
//! records and decides, the mitigator announces, and the CLI never speaks
//! to GoBGP. Approving, withdrawing and engaging the kill switch ask
//! first; releasing the kill switch is not here at all, because no API
//! token may do it.

use hyper::Method;
use serde_json::{json, Value};

use crate::args::{MitigationAction, MitigationRef, MitigationRequestArgs, Output};
use crate::client::{Call, Client};
use crate::{
    confirm, exit, fetch, field_or, get, idempotency_key, output, parse_json, print_verbatim,
    query_string, resolve_id, Io, Stop,
};

/// A read: the body verbatim under `--output json`, else `render`ed.
async fn show(
    client: &Client,
    path: String,
    io: &mut Io<'_>,
    output: Output,
    render: impl FnOnce(&Value, bool, i64) -> String,
) -> Result<Value, Stop> {
    let reply = fetch(client, get(path), io, output).await?;
    let value = parse_json(&reply.body)?;
    if output == Output::Json {
        print_verbatim(io, &reply.body);
    } else {
        let _ = write!(
            io.out,
            "{}",
            render(&value, output == Output::Wide, io.now_micros)
        );
    }
    Ok(value)
}

pub(crate) async fn list(
    client: &Client,
    query: &[(String, String)],
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let path = format!("/api/v1/mitigations{}", query_string(query));
    show(client, path, io, output, output::mitigation_list).await?;
    Ok(())
}

pub(crate) async fn detail(
    client: &Client,
    mitigation: &MitigationRef,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let path = format!("/api/v1/mitigations/{}", mitigation.0);
    show(client, path, io, output, |m, _, now| {
        output::mitigation(m, now)
    })
    .await?;
    Ok(())
}

pub(crate) async fn history(
    client: &Client,
    mitigation: &MitigationRef,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let path = format!("/api/v1/mitigations/{}/history", mitigation.0);
    show(client, path, io, output, |page, _, _| {
        output::mitigation_history(page)
    })
    .await?;
    Ok(())
}

/// `mitigations request`: one `POST` with one idempotency key. It
/// announces nothing; it waits for a `noc_lead` to approve it.
pub(crate) async fn request(
    client: &Client,
    request: &MitigationRequestArgs,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let incident = match &request.incident {
        Some(incident) => Some(resolve_id(client, incident, io, output).await?),
        None => None,
    };
    let mut flow = json!({
        "protocol": request.protocol,
        "source": request.source,
        "source_port": request.source_port,
        "destination_port": request.destination_port,
    });
    let flow_map = flow.as_object_mut().expect("an object");
    flow_map.retain(|_, value| !value.is_null());
    let has_flow = !flow_map.is_empty();
    let mut body = json!({
        "prefix": request.prefix,
        "action": request.action,
        "reason": request.reason,
        "duration_seconds": request.duration.as_secs(),
        "incident_id": incident,
        "bytes_per_second": request.bytes_per_second,
    });
    let object = body.as_object_mut().expect("an object");
    object.retain(|_, value| !value.is_null());
    if has_flow {
        object.insert("flow".into(), flow);
    }
    let call = Call {
        method: Method::POST,
        path: "/api/v1/mitigations".to_string(),
        body: Some(body.to_string().into_bytes()),
        idempotency_key: Some(idempotency_key(io.now_micros)),
    };
    let reply = fetch(client, call, io, output).await?;
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Ok(());
    }
    let created = parse_json(&reply.body)?;
    let _ = writeln!(
        io.out,
        "Requested {} {} ({}); state {}. A noc_lead must approve it before anything is announced.",
        field_or(&created, "action", "?"),
        field_or(&created, "prefix", "?"),
        field_or(&created, "mitigation_id", "?"),
        field_or(&created, "state", "?"),
    );
    Ok(())
}

/// The question before `action`, if it needs one: approving (it will be
/// announced) and withdrawing (the protection ends).
fn question(action: &MitigationAction, current: Option<&Value>, id: &str) -> Option<String> {
    let what = match current {
        Some(m) => format!(
            "{} of {} ({}, now {})",
            field_or(m, "action", "?"),
            field_or(m, "prefix", "?"),
            output::clean(id),
            field_or(m, "state", "?")
        ),
        None => output::clean(id),
    };
    match action {
        MitigationAction::Approve => {
            let by = current
                .map(|m| format!(", requested by {}", field_or(m, "requested_by", "?")))
                .unwrap_or_default();
            Some(format!(
                "Approve {what}{by}? The mitigator will announce it to BGP unless the \
                 deployment is in dry-run."
            ))
        }
        MitigationAction::Withdraw { .. } => Some(format!(
            "Withdraw {what}? Its route is taken down and the traffic it held back returns."
        )),
        MitigationAction::Reject { .. } => None,
    }
}

/// `mitigations approve|reject|withdraw`: read the version (unless
/// pinned), confirm where asked, then one `POST` with one key.
pub(crate) async fn change(
    client: &Client,
    mitigation: &MitigationRef,
    action: &MitigationAction,
    expected_version: Option<u64>,
    yes: bool,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let id = &mitigation.0;
    let asks = !matches!(action, MitigationAction::Reject { .. }) && !yes;
    let current = if expected_version.is_none() || asks {
        let reply = fetch(client, get(format!("/api/v1/mitigations/{id}")), io, output).await?;
        Some(parse_json(&reply.body)?)
    } else {
        None
    };
    let version = expected_version
        .or_else(|| current.as_ref().and_then(|m| m["version"].as_u64()))
        .ok_or_else(|| Stop::new(exit::FAILURE, "Error: the mitigation has no version\n"))?;
    let verb = action.verb();
    if let Some(question) = question(action, current.as_ref(), id) {
        if !yes {
            confirm(io, &question, &format!("mitigations {verb}"))?;
        }
    }
    let body = match action {
        MitigationAction::Approve => json!({ "expected_version": version }),
        MitigationAction::Reject { reason } | MitigationAction::Withdraw { reason } => {
            json!({ "expected_version": version, "reason": reason })
        }
    };
    let call = Call {
        method: Method::POST,
        path: format!("/api/v1/mitigations/{id}/{verb}"),
        body: Some(body.to_string().into_bytes()),
        idempotency_key: Some(idempotency_key(io.now_micros)),
    };
    let reply = match fetch(client, call, io, output).await {
        Ok(reply) => reply,
        Err(mut stop) => {
            if stop.code == exit::CONFLICT && output != Output::Json {
                stop.message.push_str(&format!(
                    "\nRe-read the mitigation and decide again:\n  wetechinetmonctl mitigations show {id}\n"
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
        "{} {}: {verb} done; state {}, version {}",
        field_or(&after, "action", "?"),
        field_or(&after, "prefix", "?"),
        field_or(&after, "state", "?"),
        field_or(&after, "version", "?"),
    );
    Ok(())
}

pub(crate) async fn kill_switch_status(
    client: &Client,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let path = "/api/v1/mitigation-controls/kill-switch".to_string();
    show(client, path, io, output, |k, _, now| {
        output::kill_switch(k, now)
    })
    .await?;
    Ok(())
}

/// `kill-switch engage`: every live mitigation is withdrawn and nothing
/// new is announced until it is released on the API host.
pub(crate) async fn kill_switch_engage(
    client: &Client,
    reason: &str,
    yes: bool,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    if !yes {
        confirm(
            io,
            "Engage the kill switch? Every live mitigation is withdrawn, nothing new is \
             announced, and only the API host can release it.",
            "kill-switch engage",
        )?;
    }
    let call = Call {
        method: Method::PUT,
        path: "/api/v1/mitigation-controls/kill-switch".to_string(),
        body: Some(
            json!({ "engaged": true, "reason": reason })
                .to_string()
                .into_bytes(),
        ),
        idempotency_key: Some(idempotency_key(io.now_micros)),
    };
    let reply = fetch(client, call, io, output).await?;
    if output == Output::Json {
        print_verbatim(io, &reply.body);
        return Ok(());
    }
    let after = parse_json(&reply.body)?;
    let _ = write!(io.out, "{}", output::kill_switch(&after, io.now_micros));
    Ok(())
}

pub(crate) async fn bgp_routes(
    client: &Client,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    show(
        client,
        "/api/v1/bgp/routes".to_string(),
        io,
        output,
        |page, wide, _| output::bgp_routes(page, wide),
    )
    .await?;
    Ok(())
}

pub(crate) async fn bgp_peers(
    client: &Client,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let page = show(
        client,
        "/api/v1/bgp/peers".to_string(),
        io,
        output,
        output::bgp_peers,
    )
    .await?;
    if output != Output::Json {
        if let Some(note) = output::stale_peers(&page, io.now_micros) {
            let _ = writeln!(io.err, "{note}");
        }
    }
    Ok(())
}
