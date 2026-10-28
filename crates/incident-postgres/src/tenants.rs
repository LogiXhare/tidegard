//! The tenant registry (Phase 8A, ADR 0060): tenants, their status, and
//! the prefixes each owns (BQ-20).
//!
//! V22 holds the rules, so they hold for every writer: no two prefixes
//! overlap, in any tenant; no claim is wider than `/8` or `/16`; no tenant
//! is called `platform`. The checks here repeat them only to name the
//! problem before the database refuses.
//!
//! Callers authorize. The API requires a platform role (8A-3); the host's
//! `tidegard-api tenant` command has the host's own access to the
//! database, as `tidegard-api token` does.

use std::net::IpAddr;

use tidegard_mitigation::prefix::{Prefix, PrefixError};
use tokio_postgres::error::SqlState;
use tokio_postgres::GenericClient;

/// The scope of deployment-wide records. Never a tenant.
pub const PLATFORM: &str = "platform";

/// The narrowest an IPv4 claim may be measured from: `/8`.
pub const IPV4_WIDEST: u8 = 8;
/// The same for IPv6: `/16`.
pub const IPV6_WIDEST: u8 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    /// Its tokens and sessions are refused; its data is kept.
    Suspended,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Suspended => "suspended",
        }
    }

    pub fn parse(text: &str) -> Option<TenantStatus> {
        match text {
            "active" => Some(TenantStatus::Active),
            "suspended" => Some(TenantStatus::Suspended),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub tenant_id: String,
    pub display_name: String,
    pub status: TenantStatus,
    pub created_at: String,
    pub updated_at: String,
}

/// One registered prefix and the tenant that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    pub prefix: Prefix,
    pub tenant_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("a tenant id is 1 to 128 characters and is not `platform`")]
    InvalidId,
    #[error("a display name is 1 to 200 characters")]
    InvalidName,
    #[error("tenant {0:?} already exists")]
    Exists(String),
    #[error("no tenant {0:?}")]
    NoSuchTenant(String),
    #[error("{0}")]
    Prefix(#[from] PrefixError),
    #[error("{0} is wider than /{IPV4_WIDEST} (IPv4) or /{IPV6_WIDEST} (IPv6)")]
    TooWide(Prefix),
    #[error("{prefix} overlaps {existing}, registered to tenant {owner:?}")]
    Overlaps {
        prefix: Prefix,
        existing: Prefix,
        owner: String,
    },
    /// Another writer registered an overlapping prefix at the same moment.
    #[error("{0} overlaps a prefix registered at the same moment")]
    Contended(Prefix),
    #[error("a row the database returned is not valid: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Database(#[from] tokio_postgres::Error),
}

fn check_id(tenant_id: &str) -> Result<(), RegistryError> {
    if (1..=128).contains(&tenant_id.chars().count()) && tenant_id != PLATFORM {
        Ok(())
    } else {
        Err(RegistryError::InvalidId)
    }
}

fn check_name(display_name: &str) -> Result<(), RegistryError> {
    if (1..=200).contains(&display_name.chars().count()) {
        Ok(())
    } else {
        Err(RegistryError::InvalidName)
    }
}

fn check_width(prefix: &Prefix) -> Result<(), RegistryError> {
    let widest = if prefix.is_ipv4() {
        IPV4_WIDEST
    } else {
        IPV6_WIDEST
    };
    if prefix.length() >= widest {
        Ok(())
    } else {
        Err(RegistryError::TooWide(*prefix))
    }
}

fn violates(error: &tokio_postgres::Error, state: &SqlState) -> bool {
    error.code() == Some(state)
}

const COLUMNS: &str = "tenant_id, display_name, status, \
    created_at::text AS created_at, updated_at::text AS updated_at";

fn tenant_from(row: &tokio_postgres::Row) -> Result<Tenant, RegistryError> {
    let status: String = row.get("status");
    Ok(Tenant {
        tenant_id: row.get("tenant_id"),
        display_name: row.get("display_name"),
        status: TenantStatus::parse(&status)
            .ok_or_else(|| RegistryError::Corrupt(format!("status {status:?}")))?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn prefix_from(text: &str) -> Result<Prefix, RegistryError> {
    text.parse()
        .map_err(|_| RegistryError::Corrupt(format!("prefix {text:?}")))
}

/// Registers a new, active tenant.
pub async fn create(
    client: &impl GenericClient,
    tenant_id: &str,
    display_name: &str,
) -> Result<Tenant, RegistryError> {
    check_id(tenant_id)?;
    check_name(display_name)?;
    let sql = format!(
        "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $2) RETURNING {COLUMNS}"
    );
    match client.query_one(&sql, &[&tenant_id, &display_name]).await {
        Ok(row) => tenant_from(&row),
        Err(error) if violates(&error, &SqlState::UNIQUE_VIOLATION) => {
            Err(RegistryError::Exists(tenant_id.to_string()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Registers `tenant_id`, named by its id, unless it already exists.
/// `true` if it was registered now. The host's `token create` uses this,
/// so a v1.0.0 script that names a new tenant keeps working.
pub async fn ensure(client: &impl GenericClient, tenant_id: &str) -> Result<bool, RegistryError> {
    check_id(tenant_id)?;
    let inserted = client
        .execute(
            "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1) \
             ON CONFLICT (tenant_id) DO NOTHING",
            &[&tenant_id],
        )
        .await?;
    Ok(inserted == 1)
}

pub async fn get(
    client: &impl GenericClient,
    tenant_id: &str,
) -> Result<Option<Tenant>, RegistryError> {
    let sql = format!("SELECT {COLUMNS} FROM tenants WHERE tenant_id = $1");
    client
        .query_opt(&sql, &[&tenant_id])
        .await?
        .as_ref()
        .map(tenant_from)
        .transpose()
}

pub async fn list(client: &impl GenericClient) -> Result<Vec<Tenant>, RegistryError> {
    let sql = format!("SELECT {COLUMNS} FROM tenants ORDER BY tenant_id");
    client
        .query(&sql, &[])
        .await?
        .iter()
        .map(tenant_from)
        .collect()
}

/// Suspends or reactivates a tenant. Setting the status it already has
/// changes nothing.
pub async fn set_status(
    client: &impl GenericClient,
    tenant_id: &str,
    status: TenantStatus,
) -> Result<Tenant, RegistryError> {
    let sql = format!(
        "UPDATE tenants SET status = $2, \
             updated_at = CASE WHEN status = $2 THEN updated_at ELSE transaction_timestamp() END \
         WHERE tenant_id = $1 RETURNING {COLUMNS}"
    );
    client
        .query_opt(&sql, &[&tenant_id, &status.as_str()])
        .await?
        .as_ref()
        .map(tenant_from)
        .transpose()?
        .ok_or_else(|| RegistryError::NoSuchTenant(tenant_id.to_string()))
}

/// Registers `prefix` to `tenant_id`. Refused if it overlaps any
/// registered prefix, the tenant's own included.
///
/// The overlap is looked for first, so that the refusal can name it: a
/// failed insert would abort the caller's transaction before anything
/// could be read. The exclusion constraint still decides a race, which is
/// then refused without a name.
pub async fn add_prefix(
    client: &impl GenericClient,
    tenant_id: &str,
    prefix: Prefix,
) -> Result<(), RegistryError> {
    check_width(&prefix)?;
    let text = prefix.to_string();
    let found = client
        .query_opt(
            "SELECT prefix::text AS prefix, tenant_id FROM tenant_prefixes \
             WHERE prefix && $1::text::cidr ORDER BY prefix LIMIT 1",
            &[&text],
        )
        .await?;
    if let Some(row) = found {
        return Err(RegistryError::Overlaps {
            prefix,
            existing: prefix_from(row.get("prefix"))?,
            owner: row.get("tenant_id"),
        });
    }
    let result = client
        .execute(
            "INSERT INTO tenant_prefixes (prefix, tenant_id) VALUES ($1::text::cidr, $2)",
            &[&text, &tenant_id],
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if violates(&error, &SqlState::FOREIGN_KEY_VIOLATION) => {
            Err(RegistryError::NoSuchTenant(tenant_id.to_string()))
        }
        Err(error)
            if violates(&error, &SqlState::EXCLUSION_VIOLATION)
                || violates(&error, &SqlState::UNIQUE_VIOLATION) =>
        {
            Err(RegistryError::Contended(prefix))
        }
        Err(error) => Err(error.into()),
    }
}

/// `false` if `tenant_id` has no such prefix.
pub async fn remove_prefix(
    client: &impl GenericClient,
    tenant_id: &str,
    prefix: Prefix,
) -> Result<bool, RegistryError> {
    let removed = client
        .execute(
            "DELETE FROM tenant_prefixes WHERE prefix = $1::text::cidr AND tenant_id = $2",
            &[&prefix.to_string(), &tenant_id],
        )
        .await?;
    Ok(removed == 1)
}

/// One tenant's prefixes, in address order.
pub async fn prefixes(
    client: &impl GenericClient,
    tenant_id: &str,
) -> Result<Vec<Prefix>, RegistryError> {
    client
        .query(
            "SELECT prefix::text AS prefix FROM tenant_prefixes \
             WHERE tenant_id = $1 ORDER BY prefix",
            &[&tenant_id],
        )
        .await?
        .iter()
        .map(|row| prefix_from(row.get("prefix")))
        .collect()
}

/// Every registered prefix with its owner: the snapshot a service loads.
pub async fn ownership(client: &impl GenericClient) -> Result<Vec<Ownership>, RegistryError> {
    client
        .query(
            "SELECT prefix::text AS prefix, tenant_id FROM tenant_prefixes ORDER BY prefix",
            &[],
        )
        .await?
        .iter()
        .map(|row| {
            Ok(Ownership {
                prefix: prefix_from(row.get("prefix"))?,
                tenant_id: row.get("tenant_id"),
            })
        })
        .collect()
}

/// The prefix that holds `address`, and its tenant. Prefixes never
/// overlap, so there is at most one.
pub async fn owner_of(
    client: &impl GenericClient,
    address: IpAddr,
) -> Result<Option<Ownership>, RegistryError> {
    client
        .query_opt(
            "SELECT prefix::text AS prefix, tenant_id FROM tenant_prefixes \
             WHERE prefix >>= $1::text::inet",
            &[&address.to_string()],
        )
        .await?
        .map(|row| {
            Ok(Ownership {
                prefix: prefix_from(row.get("prefix"))?,
                tenant_id: row.get("tenant_id"),
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenant_id_is_bounded_and_never_platform() {
        assert!(check_id("acme").is_ok());
        assert!(check_id(&"a".repeat(128)).is_ok());
        for bad in ["", "platform"] {
            assert!(
                matches!(check_id(bad), Err(RegistryError::InvalidId)),
                "{bad:?}"
            );
        }
        assert!(matches!(
            check_id(&"a".repeat(129)),
            Err(RegistryError::InvalidId)
        ));
    }

    #[test]
    fn a_claim_is_no_wider_than_slash_8_or_slash_16() {
        for ok in [
            "10.0.0.0/8",
            "192.0.2.0/24",
            "198.51.100.7/32",
            "2001:db8::/32",
            "2001::/16",
        ] {
            assert!(check_width(&ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for wide in ["0.0.0.0/0", "8.0.0.0/7", "::/0", "2000::/15"] {
            assert!(
                matches!(
                    check_width(&wide.parse().unwrap()),
                    Err(RegistryError::TooWide(_))
                ),
                "{wide}"
            );
        }
    }

    #[test]
    fn the_status_round_trips() {
        for status in [TenantStatus::Active, TenantStatus::Suspended] {
            assert_eq!(TenantStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(TenantStatus::parse("deleted"), None);
    }
}
