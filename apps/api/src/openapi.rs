//! The OpenAPI document, generated from the handlers (ADR 0037).
//!
//! The generated document is committed at `docs/api/openapi.json`, and a
//! test fails when the two differ, so every API change arrives with a
//! reviewable spec diff. To regenerate after an intended change:
//!
//! ```sh
//! TIDEGARD_UPDATE_OPENAPI=1 cargo test -p tidegard-api openapi
//! ```

use serde::Serialize;
use utoipa::{OpenApi, ToSchema};

/// RFC 9457 problem details, as every error response carries them.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemDocument {
    /// `https://logixhare.com/tidegard/problems/` and the code, as an identifier.
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    #[schema(nullable = false)]
    pub detail: Option<String>,
    /// The stable machine-readable code; see `docs/api/error-codes.md`.
    pub error: String,
    /// The UUIDv7 also returned in `X-Request-Id`.
    pub request_id: String,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Tidegard Incident API",
        description = "Incident management REST API. Errors are RFC 9457 problem details with a stable `error` code.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        crate::healthz,
        crate::readyz,
        crate::list::list_incidents,
        crate::create::create_incident,
        crate::incidents::get_incident,
        crate::history::timeline,
        crate::history::notes,
        crate::history::detections,
        crate::history::audit,
        crate::transitions::acknowledge,
        crate::transitions::investigate,
        crate::transitions::monitor,
        crate::transitions::resolve,
        crate::transitions::close,
        crate::transitions::reopen,
        crate::transitions::suppress,
        crate::transitions::unsuppress,
        crate::transitions::assign,
        crate::transitions::unassign,
        crate::transitions::severity,
        crate::transitions::priority,
        crate::transitions::add_note,
        crate::session::sign_in,
        crate::session::current,
        crate::session::sign_out,
        crate::traffic::summary,
        crate::traffic::top,
        crate::traffic::exporters,
        crate::transitions::edit_note,
        crate::transitions::redact_note,
        crate::transitions::set_tag,
        crate::transitions::remove_tag,
        crate::export::export,
        crate::whoami::whoami,
        crate::mitigations::list_mitigations,
        crate::mitigations::request_mitigation,
        crate::mitigations::get_mitigation,
        crate::mitigations::mitigation_history,
        crate::mitigations::approve_mitigation,
        crate::mitigations::reject_mitigation,
        crate::mitigations::withdraw_mitigation,
        crate::mitigations::get_kill_switch,
        crate::mitigations::set_kill_switch,
        crate::mitigations::bgp_routes,
        crate::mitigations::bgp_peers,
    ),
    components(schemas(
        ProblemDocument,
        crate::Health,
        crate::incidents::IncidentView,
        crate::incidents::SuppressionView,
        crate::incidents::PolicyRefView,
        crate::list::IncidentSummaryView,
        crate::list::IncidentPage,
        crate::history::TimelineEntryView,
        crate::history::TimelinePage,
        crate::history::AuditEntryView,
        crate::history::AuditPage,
        crate::history::DetectionView,
        crate::history::DetectionPage,
        crate::transitions::VersionOnly,
        crate::transitions::ResolveRequest,
        crate::transitions::ClosureReasonValue,
        crate::transitions::CloseRequest,
        crate::transitions::ReopenRequest,
        crate::transitions::SuppressRequest,
        crate::transitions::AssignRequest,
        crate::transitions::SeverityValue,
        crate::transitions::SeverityRequest,
        crate::transitions::PriorityValue,
        crate::transitions::PriorityRequest,
        crate::transitions::NoteVisibilityValue,
        crate::transitions::NoteRequest,
        crate::session::SignIn,
        crate::session::SessionView,
        crate::traffic::TrafficSummary,
        crate::traffic::TrafficPoint,
        crate::traffic::TopList,
        crate::traffic::TopEntry,
        crate::traffic::ExporterList,
        crate::traffic::ExporterView,
        crate::transitions::NoteEditRequest,
        crate::transitions::NoteRedactRequest,
        crate::transitions::TagRequest,
        crate::create::TargetScope,
        crate::create::DirectionValue,
        crate::create::CreateIncidentRequest,
        crate::export::Truncation,
        crate::export::IncidentExport,
        crate::whoami::WhoAmI,
        crate::history::NoteView,
        crate::history::NoteList,
        crate::mitigations::FlowView,
        crate::mitigations::MitigationView,
        crate::mitigations::MitigationList,
        crate::mitigations::MitigationHistoryEntry,
        crate::mitigations::MitigationHistory,
        crate::mitigations::MitigationRequestBody,
        crate::mitigations::ApproveBody,
        crate::mitigations::ReasonBody,
        crate::mitigations::KillSwitchView,
        crate::mitigations::KillSwitchBody,
        crate::mitigations::BgpRoute,
        crate::mitigations::BgpRouteList,
        crate::mitigations::BgpPeer,
        crate::mitigations::BgpPeerList,
    )),
    modifiers(&BearerAuth),
    tags(
        (name = "operations", description = "Liveness and readiness"),
        (name = "incidents", description = "Incidents in the caller's tenant"),
        (name = "identity", description = "Who the bearer token identifies"),
        (name = "traffic", description = "Deployment-wide traffic, for the one traffic tenant (ADR 0042)"),
        (name = "mitigations", description = "Mitigations in the caller's tenant, the kill switch and BGP status (ADR 0050)"),
    )
)]
pub struct ApiDoc;

/// Declares the `bearer` scheme: an opaque `wnm_` API token (ADR 0038).
struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "An API token, `wnm_` and 64 hex characters, from `tidegard-api token create`.",
                    ))
                    .build(),
            ),
        );
    }
}

/// The document as committed: pretty JSON with a trailing newline.
pub fn document() -> String {
    let mut json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("the OpenAPI document serializes");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMITTED: &str = "../../docs/api/openapi.json";

    #[test]
    fn openapi_document_matches_the_committed_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(COMMITTED);
        let generated = document();
        if std::env::var_os("TIDEGARD_UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &generated).expect("write docs/api/openapi.json");
            return;
        }
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert!(
            committed == generated,
            "docs/api/openapi.json is out of date; regenerate it with \
             TIDEGARD_UPDATE_OPENAPI=1 cargo test -p tidegard-api openapi"
        );
    }
}
