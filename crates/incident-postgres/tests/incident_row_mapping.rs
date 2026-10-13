//! Row mapping tests that need no database (5B-3(b)).

mod support;

use support::{
    all_scopes, host_scope, hostgroup_scope, network_scope_with_host_bits, worked_incident,
};
use tidegard_incident::authorization::Actor;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::row::IncidentRow;

fn host_row() -> IncidentRow {
    let (uow, id) = worked_incident(&host_scope(), 1);
    IncidentRow::from_incident(uow.get(&id).unwrap()).unwrap()
}

#[test]
fn every_scope_round_trips_through_the_row_exactly() {
    for (scope, seed) in all_scopes() {
        let (uow, id) = worked_incident(&scope, seed);
        let incident = uow.get(&id).unwrap();
        let row = IncidentRow::from_incident(incident).unwrap();
        assert_eq!(&row.into_incident().unwrap(), incident);
    }
}

#[test]
fn the_worked_incident_fills_the_columns_the_round_trip_relies_on() {
    let row = host_row();
    assert_eq!(row.state, "acknowledged");
    assert_eq!(row.priority, "P1");
    assert!(row.acknowledged_at.is_some());
    assert!(row.suppression.is_some());
    assert_eq!(row.assigned_kind.as_deref(), Some("user"));
    let suppressed_by = &row.suppression.as_ref().unwrap().by;
    assert_eq!(suppressed_by.actor_type, "operator");
    assert_eq!(suppressed_by.actor_id.as_deref(), Some("op-7"));
    assert_eq!(row.created_by.actor_type, "system");
    assert_eq!(row.created_by.actor_id, None);
    assert_eq!(row.notes.len(), 1);
    assert_eq!(row.tags.len(), 2);
    let refs: Vec<(i32, &str)> = row
        .policy_refs
        .iter()
        .map(|r| (r.ref_index, r.policy_id.as_str()))
        .collect();
    assert_eq!(refs, [(0, "p-opening"), (1, "p-second")]);
}

#[test]
fn target_columns_follow_the_scope_identity() {
    let row = host_row();
    assert_eq!(row.target_type, "host");
    assert_eq!(row.target_addr.as_deref(), Some("203.0.113.90"));
    assert_eq!((row.target_network, row.target_hostgroup), (None, None));

    let (uow, id) = worked_incident(&network_scope_with_host_bits(), 1_000);
    let row = IncidentRow::from_incident(uow.get(&id).unwrap()).unwrap();
    assert_eq!(row.target_type, "network");
    assert_eq!(row.target_network.as_deref(), Some("203.0.113.77/24"));
    assert_eq!(row.address_family, 4);

    let (uow, id) = worked_incident(&hostgroup_scope(), 2_000);
    let row = IncidentRow::from_incident(uow.get(&id).unwrap()).unwrap();
    assert_eq!(row.target_type, "hostgroup");
    assert_eq!(row.target_hostgroup.as_deref(), Some("edge-routers"));
}

#[test]
fn a_platform_actor_cannot_be_stored() {
    let (uow, id) = worked_incident(&host_scope(), 1);
    let mut snapshot = uow.get(&id).unwrap().to_snapshot();
    snapshot.updated_by = Actor::Platform {
        id: "platform-admin".to_string(),
    };
    assert!(matches!(
        IncidentRow::from_snapshot(&snapshot),
        Err(PersistError::Unrepresentable {
            field: "updated_by",
            ..
        })
    ));
}

#[test]
fn a_target_type_disagreeing_with_the_correlation_key_is_corrupt() {
    let mut row = host_row();
    row.target_type = "network".to_string();
    assert!(matches!(
        row.into_snapshot(),
        Err(PersistError::Corrupt {
            column: "target_type",
            ..
        })
    ));
}

#[test]
fn a_gap_in_policy_reference_positions_is_corrupt() {
    let mut row = host_row();
    row.policy_refs[1].ref_index = 5;
    assert!(matches!(
        row.into_snapshot(),
        Err(PersistError::Corrupt {
            column: "ref_index",
            ..
        })
    ));
}

#[test]
fn stored_order_does_not_matter_to_the_load() {
    let (uow, id) = worked_incident(&host_scope(), 1);
    let mut row = IncidentRow::from_incident(uow.get(&id).unwrap()).unwrap();
    row.policy_refs.reverse();
    assert_eq!(&row.into_incident().unwrap(), uow.get(&id).unwrap());
}

#[test]
fn an_unknown_enum_value_is_corrupt() {
    let mut row = host_row();
    row.state = "paused".to_string();
    assert!(matches!(
        row.into_snapshot(),
        Err(PersistError::Corrupt {
            column: "state",
            ..
        })
    ));
}

#[test]
fn a_parseable_but_inconsistent_row_is_rejected_by_reconstitution() {
    let mut row = host_row();
    row.version = 0;
    assert!(matches!(
        row.into_incident(),
        Err(PersistError::Rejected(_))
    ));
}
