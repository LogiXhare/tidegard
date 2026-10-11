//! Every dashboard in `grafana/dashboards/` queries only metrics the code
//! registers and tables the schema creates (ADR 0041).

use std::collections::BTreeSet;
use std::path::Path;

use wetechinetmon_dashboard_check::{check_dashboard, Known};

fn known() -> Known {
    let mut metrics: BTreeSet<String> = wetechinetmon_collector::metric_names()
        .into_iter()
        .collect();
    let (manager, _registry) =
        wetechinetmon_incident_manager::metrics::ManagerMetrics::new().expect("registers");
    metrics.extend(manager.metric_names());
    let tables = wetechinetmon_storage::schema::CREATE_TABLE_STATEMENTS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    Known { metrics, tables }
}

#[test]
fn every_dashboard_queries_only_what_exists() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grafana/dashboards");
    let known = known();
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    let mut checked = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&directory)
        .expect("grafana/dashboards exists")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let json = std::fs::read_to_string(&path).unwrap();
        problems.extend(check_dashboard(&name, &json, &known, &mut seen));
        checked += 1;
    }
    assert!(
        problems.is_empty(),
        "dashboard problems:\n{}",
        problems.join("\n")
    );
    assert_eq!(checked, 4, "the four dashboards of ADR 0041");
}
