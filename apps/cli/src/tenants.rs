//! `tenants` and `tokens` (Phase 8A-4, ADR 0060).
//!
//! `tenants` is the registry, for platform roles: it names the tenant in
//! the path, so it needs no `--tenant`. `tokens` acts in one tenant: a
//! tenant principal's own, or for a platform principal the one `--tenant`
//! names. Suspending a tenant and revoking a token ask first. A token's
//! secret is printed once, when it is issued, and never again.

use hyper::Method;
use serde_json::{json, Value};

use crate::args::Output;
use crate::client::{Call, Client};
use crate::output::clean;
use crate::{confirm, encode, fetch, get, parse_json, print_verbatim, Io, Stop};

fn call(method: Method, path: String, body: Option<Value>) -> Call {
    Call {
        method,
        path,
        body: body.map(|body| body.to_string().into_bytes()),
        idempotency_key: None,
    }
}

/// Sends `call`; prints the body verbatim under `--output json`, else
/// `render`s it.
async fn send(
    client: &Client,
    call: Call,
    io: &mut Io<'_>,
    output: Output,
    render: impl FnOnce(&Value) -> String,
) -> Result<(), Stop> {
    let reply = fetch(client, call, io, output).await?;
    if output == Output::Json {
        if !reply.body.is_empty() {
            print_verbatim(io, &reply.body);
        }
        return Ok(());
    }
    let value = if reply.body.is_empty() {
        Value::Null
    } else {
        parse_json(&reply.body)?
    };
    let _ = write!(io.out, "{}", render(&value));
    Ok(())
}

fn text(value: &Value, name: &str) -> String {
    clean(value[name].as_str().unwrap_or("-"))
}

/// Rows as aligned columns, under `header`.
fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        let mut out = String::new();
        for (index, (cell, width)) in cells.iter().zip(&widths).enumerate() {
            if index + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<width$}  "));
            }
        }
        out.trim_end().to_string() + "\n"
    };
    let mut out = line(header.iter().map(|h| h.to_string()).collect());
    for row in rows {
        out.push_str(&line(row.clone()));
    }
    out
}

fn tenant_row(tenant: &Value) -> Vec<String> {
    vec![
        text(tenant, "tenant_id"),
        text(tenant, "status"),
        text(tenant, "display_name"),
        text(tenant, "created_at"),
    ]
}

fn tenant_list(page: &Value) -> String {
    let rows: Vec<Vec<String>> = page["tenants"]
        .as_array()
        .map(|all| all.iter().map(tenant_row).collect())
        .unwrap_or_default();
    table(&["TENANT", "STATUS", "NAME", "CREATED"], &rows)
}

fn tenant(value: &Value) -> String {
    let mut out = format!(
        "Tenant   {}\nName     {}\nStatus   {}\nCreated  {}\nUpdated  {}\n",
        text(value, "tenant_id"),
        text(value, "display_name"),
        text(value, "status"),
        text(value, "created_at"),
        text(value, "updated_at"),
    );
    if let Some(prefixes) = value["prefixes"].as_array() {
        out.push_str("Prefixes");
        if prefixes.is_empty() {
            out.push_str(" none\n");
        } else {
            for (index, prefix) in prefixes.iter().enumerate() {
                let gap = if index == 0 { " " } else { "         " };
                out.push_str(&format!("{gap}{}\n", clean(prefix.as_str().unwrap_or("-"))));
            }
        }
    }
    out
}

pub(crate) async fn list(client: &Client, io: &mut Io<'_>, output: Output) -> Result<(), Stop> {
    let call = get("/api/v1/platform/tenants".to_string());
    send(client, call, io, output, tenant_list).await
}

pub(crate) async fn show(
    client: &Client,
    tenant_id: &str,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let call = get(format!("/api/v1/platform/tenants/{}", encode(tenant_id)));
    send(client, call, io, output, tenant).await
}

pub(crate) async fn create(
    client: &Client,
    tenant_id: &str,
    name: Option<&str>,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let mut body = json!({"tenant_id": tenant_id});
    if let Some(name) = name {
        body["display_name"] = json!(name);
    }
    let call = call(
        Method::POST,
        "/api/v1/platform/tenants".to_string(),
        Some(body),
    );
    send(client, call, io, output, tenant).await
}

/// Suspends (asking first: it locks the tenant out at once) or
/// reactivates a tenant.
pub(crate) async fn set_status(
    client: &Client,
    tenant_id: &str,
    suspend: bool,
    yes: bool,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    if suspend && !yes {
        confirm(
            io,
            &format!(
                "Suspend tenant {}? Its tokens and sessions stop working at once.",
                clean(tenant_id)
            ),
            "tenants suspend",
        )?;
    }
    let verb = if suspend { "suspend" } else { "activate" };
    let path = format!("/api/v1/platform/tenants/{}/{verb}", encode(tenant_id));
    send(client, call(Method::POST, path, None), io, output, tenant).await
}

pub(crate) async fn add_prefix(
    client: &Client,
    tenant_id: &str,
    prefix: &str,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let path = format!("/api/v1/platform/tenants/{}/prefixes", encode(tenant_id));
    let body = json!({"prefix": prefix});
    send(
        client,
        call(Method::POST, path, Some(body)),
        io,
        output,
        |added| {
            format!(
                "{} registered to {}\n",
                text(added, "prefix"),
                text(added, "tenant_id")
            )
        },
    )
    .await
}

pub(crate) async fn remove_prefix(
    client: &Client,
    tenant_id: &str,
    prefix: &str,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    // The prefix's slash is the path separator between its address and
    // its length (ADR 0060); each half is encoded on its own.
    let Some((address, length)) = prefix.split_once('/') else {
        return Err(Stop::new(
            crate::exit::USAGE,
            format!(
                "Error: {:?} is not a prefix, such as 192.0.2.0/24\n",
                clean(prefix)
            ),
        ));
    };
    let path = format!(
        "/api/v1/platform/tenants/{}/prefixes/{}/{}",
        encode(tenant_id),
        encode(address),
        encode(length)
    );
    let shown = format!("{} removed from {}\n", clean(prefix), clean(tenant_id));
    send(client, call(Method::DELETE, path, None), io, output, |_| {
        shown
    })
    .await
}

fn token_list(page: &Value) -> String {
    let rows: Vec<Vec<String>> = page["tokens"]
        .as_array()
        .map(|all| {
            all.iter()
                .map(|token| {
                    vec![
                        text(token, "token_id"),
                        format!("{}:{}", text(token, "actor_type"), text(token, "actor_id")),
                        text(token, "role"),
                        text(token, "expires_at"),
                        match token["revoked_at"].as_str() {
                            Some(at) => format!("revoked {}", clean(at)),
                            None => "live".to_string(),
                        },
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    table(&["ID", "ACTOR", "ROLE", "EXPIRES", "STATE"], &rows)
}

pub(crate) async fn tokens(client: &Client, io: &mut Io<'_>, output: Output) -> Result<(), Stop> {
    let call = get("/api/v1/tokens".to_string());
    send(client, call, io, output, token_list).await
}

/// What `tokens create` asks the API for.
pub(crate) struct NewToken<'a> {
    pub actor_id: &'a str,
    pub role: &'a str,
    pub actor_type: Option<&'a str>,
    pub days: Option<u32>,
    pub description: Option<&'a str>,
}

pub(crate) async fn issue(
    client: &Client,
    new: &NewToken<'_>,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    let mut body = json!({
        "actor_id": new.actor_id,
        "role": new.role,
        "actor_type": new.actor_type,
        "lifetime_days": new.days,
        "description": new.description,
    });
    body.as_object_mut()
        .expect("an object")
        .retain(|_, value| !value.is_null());
    let call = call(Method::POST, "/api/v1/tokens".to_string(), Some(body));
    send(client, call, io, output, |issued| {
        format!(
            "token_id:   {}\nexpires_at: {}\ntoken:      {}\n\
             Store the token now: it is not shown again and cannot be recovered.\n",
            text(issued, "token_id"),
            text(issued, "expires_at"),
            text(issued, "token"),
        )
    })
    .await
}

pub(crate) async fn revoke(
    client: &Client,
    token_id: &str,
    yes: bool,
    io: &mut Io<'_>,
    output: Output,
) -> Result<(), Stop> {
    if !yes {
        confirm(
            io,
            &format!(
                "Revoke token {}? It and its sessions stop working at once.",
                clean(token_id)
            ),
            "tokens revoke",
        )?;
    }
    let path = format!("/api/v1/tokens/{}/revoke", encode(token_id));
    let shown = format!("revoked {}\n", clean(token_id));
    send(client, call(Method::POST, path, None), io, output, |_| {
        shown
    })
    .await
}
