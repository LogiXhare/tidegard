//! An incident's mitigation and notification status (FU-64, ADR 0050).
//!
//! Phase 5 reported both as the constant `none`. Since Phase 6 notifies
//! and Phase 7 mitigates, both are derived from the records:
//!
//! - **Mitigation:** the incident's most live mitigation, or else the one
//!   that ended last: `none`, `pending_approval`, `approved`, `active`,
//!   `dry_run`, `withdrawing`, `withdrawn`, `rejected`, `expired` or
//!   `failed`.
//! - **Notification:** the latest outcome per channel on the timeline:
//!   `none`, `delivered` (every channel), `partial`, or `failed` (none
//!   delivered).
//!
//! Both are read within the incident's tenant only.

use tidegard_incident::correlation::TenantId;
use tidegard_mitigation::MitigationState;
use tokio_postgres::GenericClient;

use crate::error::PersistError;
use crate::mitigation::mitigation_status;

const MITIGATION: &str = "\
SELECT state, dry_run FROM mitigations
WHERE tenant_id = $1 AND incident_id = $2::text::uuid
ORDER BY CASE WHEN state IN ('withdrawn', 'rejected', 'expired', 'failed') THEN 1 ELSE 0 END,
    updated_at DESC
LIMIT 1";

// The payload's shape is the domain's; the channel and outcome are found
// wherever they sit in it.
const NOTIFICATION: &str = "\
SELECT DISTINCT ON (channel) outcome FROM (
    SELECT jsonb_path_query_first(payload, '$.**.channel') #>> '{}' AS channel,
        jsonb_path_query_first(payload, '$.**.outcome') #>> '{}' AS outcome,
        timeline_id
    FROM incident_timeline
    WHERE tenant_id = $1 AND incident_id = $2::text::uuid
      AND entry_type = 'notification_result'
) attempts
ORDER BY channel, timeline_id DESC";

pub async fn incident_mitigation_status(
    client: &impl GenericClient,
    tenant: &TenantId,
    incident_id: &str,
) -> Result<&'static str, PersistError> {
    let Some(row) = client
        .query_opt(MITIGATION, &[&tenant.as_str(), &incident_id])
        .await?
    else {
        return Ok("none");
    };
    let state: String = row.try_get("state")?;
    let state = MitigationState::parse(&state)
        .ok_or_else(|| PersistError::corrupt("state", "unknown state"))?;
    Ok(mitigation_status(state, row.try_get("dry_run")?))
}

pub async fn incident_notification_status(
    client: &impl GenericClient,
    tenant: &TenantId,
    incident_id: &str,
) -> Result<&'static str, PersistError> {
    let outcomes: Vec<Option<String>> = client
        .query(NOTIFICATION, &[&tenant.as_str(), &incident_id])
        .await?
        .iter()
        .map(|row| row.try_get("outcome"))
        .collect::<Result<_, _>>()?;
    Ok(notification_status(&outcomes))
}

/// The summary of each channel's latest outcome.
pub fn notification_status(latest: &[Option<String>]) -> &'static str {
    if latest.is_empty() {
        return "none";
    }
    let delivered = latest
        .iter()
        .filter(|o| o.as_deref() == Some("delivered"))
        .count();
    match delivered {
        0 => "failed",
        n if n == latest.len() => "delivered",
        _ => "partial",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcomes(list: &[&str]) -> Vec<Option<String>> {
        list.iter().map(|o| Some(o.to_string())).collect()
    }

    #[test]
    fn notification_status_summarises_each_channels_latest_outcome() {
        assert_eq!(notification_status(&[]), "none");
        assert_eq!(
            notification_status(&outcomes(&["delivered", "delivered"])),
            "delivered"
        );
        assert_eq!(
            notification_status(&outcomes(&["delivered", "failed"])),
            "partial"
        );
        assert_eq!(
            notification_status(&outcomes(&["refused", "failed"])),
            "failed"
        );
    }

    #[test]
    fn mitigation_status_names_every_state() {
        use MitigationState::*;
        for (state, dry, expected) in [
            (Proposed, None, "pending_approval"),
            (Requested, None, "pending_approval"),
            (Approved, None, "approved"),
            (Announcing, Some(false), "active"),
            (Active, Some(true), "dry_run"),
            (Withdrawing, Some(false), "withdrawing"),
            (Withdrawn, Some(false), "withdrawn"),
            (Rejected, None, "rejected"),
            (Expired, None, "expired"),
            (Failed, Some(false), "failed"),
        ] {
            assert_eq!(mitigation_status(state, dry), expected, "{state:?}");
        }
    }
}
