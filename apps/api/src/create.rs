//! `POST /api/v1/incidents`: an operator opens an incident (5D-9, ADR 0039).
//!
//! For something the detector cannot see, such as an upstream's report.
//! It is not the ingestion path: detection events arrive through the
//! inbox, never over HTTP.
//!
//! - **Needs `incident.create`** (`senior_operator` and above) and an
//!   `Idempotency-Key`: a retry with the same key and body answers with
//!   the incident the first call opened.
//! - **The target is the one a detection would name,** so the incident
//!   takes the same correlation key. Where an incident for that target is
//!   already active the request is `409 incident.duplicate_active`, with
//!   that incident's `incident_id`; while this one is active, detections
//!   for the target attach to it.
//! - **Answers `201`** with the incident and a `Location` header.

use std::net::IpAddr;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use tidegard_detector::{AddressFamily, ScopeId, ScopeType, TrafficDirection};
use tidegard_incident::manual::ManualIncident;
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::queries;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::incidents::{limit, IncidentView};
use crate::problem::{ErrorCode, Problem};
use crate::transitions::{idempotency_key, PriorityValue, SeverityValue};
use crate::AppState;

/// What kind of target, in the detector's own vocabulary.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetScope {
    /// `target` is one address.
    Host,
    /// `target` is a configured prefix, such as `203.0.113.0/25`.
    Prefix,
    /// `target` is the IPv4 /24 containing an address, such as `203.0.113.0/24`.
    Slash24,
    /// `target` is a hostgroup name; `address_family` is required.
    HostgroupTotal,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectionValue {
    Incoming,
    Outgoing,
    Internal,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateIncidentRequest {
    /// Up to 200 characters.
    pub title: String,
    /// Up to 8000 characters.
    pub description: Option<String>,
    pub severity: SeverityValue,
    /// Defaults from the severity: critical P1, major P2, minor P3, info P4.
    pub priority: Option<PriorityValue>,
    pub target_scope: TargetScope,
    /// An address, a network in CIDR form, or a hostgroup name.
    pub target: String,
    pub direction: DirectionValue,
    /// 4 or 6. Taken from `target` when it is an address or network;
    /// required for `hostgroup_total`.
    pub address_family: Option<u8>,
}

fn invalid(detail: &str) -> Problem {
    Problem::new(ErrorCode::InvalidRequest).with_detail(detail.to_string())
}

fn network(text: &str) -> Result<(IpAddr, u8), Problem> {
    let (addr, len) = text
        .split_once('/')
        .ok_or_else(|| invalid("target must be a network in CIDR form"))?;
    let addr: IpAddr = addr
        .parse()
        .map_err(|_| invalid("target is not an IP address"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| invalid("target has no valid prefix length"))?;
    Ok((addr, len))
}

/// The request as the domain's typed manual incident. Shape errors are
/// `400` here; whether the parts agree is the domain's `422`.
pub fn manual_incident(request: CreateIncidentRequest) -> Result<ManualIncident, Problem> {
    let (target_type, target_identity) = match request.target_scope {
        TargetScope::Host => {
            let addr: IpAddr = request
                .target
                .parse()
                .map_err(|_| invalid("target is not an IP address"))?;
            (ScopeType::Host, ScopeId::Host { addr })
        }
        TargetScope::Prefix => {
            let (addr, prefix_len) = network(&request.target)?;
            (ScopeType::Prefix, ScopeId::Network { addr, prefix_len })
        }
        TargetScope::Slash24 => {
            let (addr, prefix_len) = network(&request.target)?;
            (ScopeType::Slash24, ScopeId::Network { addr, prefix_len })
        }
        TargetScope::HostgroupTotal => (
            ScopeType::HostgroupTotal,
            ScopeId::Hostgroup {
                name: request.target.clone(),
            },
        ),
    };
    let derived = match &target_identity {
        ScopeId::Host { addr } | ScopeId::Network { addr, .. } => Some(AddressFamily::of(*addr)),
        ScopeId::Hostgroup { .. } => None,
    };
    let given = match request.address_family {
        None => None,
        Some(4) => Some(AddressFamily::Ipv4),
        Some(6) => Some(AddressFamily::Ipv6),
        Some(_) => return Err(invalid("address_family must be 4 or 6")),
    };
    let address_family = match (derived, given) {
        (Some(derived), None) => derived,
        (None, Some(given)) => given,
        (Some(derived), Some(given)) if derived == given => derived,
        (Some(_), Some(_)) => {
            return Err(invalid(
                "address_family does not match the target's address",
            ))
        }
        (None, None) => return Err(invalid("address_family is required for a hostgroup")),
    };
    Ok(ManualIncident {
        title: request.title,
        description: request.description,
        severity: request.severity.into(),
        priority: request.priority.map(Into::into),
        target_type,
        target_identity,
        direction: match request.direction {
            DirectionValue::Incoming => TrafficDirection::Incoming,
            DirectionValue::Outgoing => TrafficDirection::Outgoing,
            DirectionValue::Internal => TrafficDirection::Internal,
        },
        address_family,
    })
}

/// Opens an incident by hand. Needs `incident.create`.
#[utoipa::path(
    post,
    path = "/api/v1/incidents",
    tag = "incidents",
    params(
        ("Idempotency-Key" = String, Header, description = "16 to 255 characters; a retry with the same key and body answers with the incident the first call opened"),
    ),
    request_body(content = CreateIncidentRequest, content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The incident opened, or on a replay the one the first call opened", body = IncidentView,
            headers(("Location" = String, description = "The incident's URL"))),
        (status = 400, description = "Bad header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.create", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "An incident for the target is already active (its incident_id is given), the key was reused, or a limit is reached", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 413, description = "The body is over 64 KiB", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "The title, description or target is invalid", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn create_incident(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        let key = idempotency_key(&headers)?;
        let request = manual_incident(crate::body::json(&headers, body)?)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool)
            .await
            .map_err(|error| Problem::from(&error))?;
        let id = state
            .incidents
            .create_manual_incident(&mut client, &auth, &request, Some(key))
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        let incident = queries::get_incident(&mut client, &auth, &id)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        IncidentView::from_incident(&incident)?
            .with_statuses(&**client)
            .await
    }
    .await;
    match result {
        Ok(view) => {
            let location = format!("/api/v1/incidents/{}", view.incident_id);
            let mut response = (StatusCode::CREATED, Json(view)).into_response();
            if let Ok(value) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(header::LOCATION, value);
            }
            response
        }
        Err(problem) => problem.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(scope: TargetScope, target: &str, family: Option<u8>) -> CreateIncidentRequest {
        CreateIncidentRequest {
            title: "Upstream report".into(),
            description: None,
            severity: SeverityValue::Major,
            priority: None,
            target_scope: scope,
            target: target.into(),
            direction: DirectionValue::Incoming,
            address_family: family,
        }
    }

    #[test]
    fn the_family_comes_from_the_target_or_must_be_given() {
        let host = manual_incident(request(TargetScope::Host, "2001:db8::1", None)).unwrap();
        assert_eq!(host.address_family, AddressFamily::Ipv6);
        assert!(manual_incident(request(TargetScope::HostgroupTotal, "edge", None)).is_err());
        assert!(manual_incident(request(TargetScope::HostgroupTotal, "edge", Some(4))).is_ok());
        assert!(manual_incident(request(TargetScope::Host, "203.0.113.5", Some(6))).is_err());
        assert!(manual_incident(request(TargetScope::Host, "203.0.113.5", Some(5))).is_err());
    }

    #[test]
    fn shapes_are_checked_before_the_domain() {
        assert!(manual_incident(request(TargetScope::Host, "not-an-ip", None)).is_err());
        assert!(manual_incident(request(TargetScope::Prefix, "203.0.113.0", None)).is_err());
        assert!(manual_incident(request(TargetScope::Prefix, "203.0.113.0/x", None)).is_err());
        let prefix = manual_incident(request(TargetScope::Prefix, "203.0.113.0/25", None)).unwrap();
        assert_eq!(
            prefix.target_identity,
            ScopeId::Network {
                addr: "203.0.113.0".parse().unwrap(),
                prefix_len: 25
            }
        );
    }
}
