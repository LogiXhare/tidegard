//! Milestone 5F: the incident persistence benchmark (the persistence plan's
//! performance-test plan).
//!
//! `#[ignore]`d: it takes minutes and measures, rather than checks. The
//! Benchmark workflow runs it against an ephemeral PostgreSQL and prints a
//! Markdown table; `docs/operations/capacity-planning.md` publishes the
//! numbers with the machine they came from. Run it by hand with:
//!
//! ```sh
//! WETECHINETMON_INCIDENT_POSTGRES_TEST_URL=... cargo test --release \
//!   -p wetechinetmon-incident-postgres --test benchmark -- --ignored --nocapture
//! ```
//!
//! It only connects to the opt-in, ephemeral database named by
//! `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`, and resets its schema.
//!
//! No benchmarking crate: `std::time::Instant` around each call, and
//! percentiles over the sorted samples. Each figure is one call's latency
//! from the client, including the network round trips the service makes.

mod support;

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{event, in_episode, operator, Scope};
use tokio_postgres::Client;
use wetechinetmon_detector::{DetectionEvent, EventKind, MetricKind, ScopeId, ScopeType};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use wetechinetmon_incident::clock::SystemClock;
use wetechinetmon_incident::command::Command;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::idempotency::IdempotencyKey;
use wetechinetmon_incident::incident::NoteVisibility;
use wetechinetmon_incident::unit_of_work::IngestOutcomeKind;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::outbox::{OutboxConsumer, OutboxPolicy};
use wetechinetmon_incident_postgres::platform::PlatformAuthority;
use wetechinetmon_incident_postgres::queries::{
    list_incidents, timeline, ListFilter, ListSort, SortOrder,
};
use wetechinetmon_incident_postgres::service::IncidentPersistence;

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";

/// Tenants the history is spread over; the measured calls use the first.
const TENANTS: [&str; 4] = ["bench-a", "bench-b", "bench-c", "bench-d"];
/// Incidents already in the database when each round is measured.
const HISTORY_SIZES: [u32; 2] = [1_000, 10_000];
/// Calls measured per operation, per round.
const SAMPLES: u32 = 300;
/// Concurrent workers, each on its own connection, for the throughput run.
const WORKERS: [u32; 3] = [1, 4, 8];
/// New incidents each worker opens in the throughput run.
const PER_WORKER: u32 = 200;

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("must be able to connect to the configured ephemeral test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection closed: {error}");
        }
    });
    client
}

/// The `n`th host target of `tenant`.
fn host(tenant: &'static str, n: u32) -> Scope {
    Scope {
        tenant,
        scope_type: ScopeType::Host,
        scope_id: ScopeId::Host {
            addr: IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n)),
        },
    }
}

/// The opening event of target `n`'s own detection episode.
fn opening(scope: &Scope, n: u32) -> DetectionEvent {
    in_episode(
        event(scope, 1, EventKind::Started, "p-bench", MetricKind::Bps),
        &format!("det-{n}"),
    )
}

/// Wired as the API wires it: UUIDv7 ids and the system clock.
fn service() -> IncidentPersistence {
    IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    )
}

struct Stats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

fn stats(mut samples: Vec<Duration>) -> Stats {
    samples.sort_unstable();
    let at = |percent: usize| samples[(samples.len() * percent / 100).min(samples.len() - 1)];
    Stats {
        p50: at(50),
        p95: at(95),
        p99: at(99),
        max: *samples.last().unwrap(),
    }
}

fn ms(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1_000.0)
}

/// Opens `count` incidents for `tenant`, numbered from `first`.
async fn open_incidents(
    client: &mut Client,
    service: &IncidentPersistence,
    tenant: &'static str,
    first: u32,
    count: u32,
) -> Vec<IncidentId> {
    let correlator = AuthorizationContext::correlator(TenantId::new(tenant));
    let mut ids = Vec::with_capacity(count as usize);
    for n in first..first + count {
        let scope = host(tenant, n);
        let result = service
            .ingest_detection_event(client, &correlator, &opening(&scope, n))
            .await
            .expect("committed")
            .expect("the domain accepts the event");
        assert_eq!(result.outcome_kind, IngestOutcomeKind::Created);
        ids.push(result.incident_id.unwrap());
    }
    ids
}

/// Grows the history to `total` incidents spread over every tenant, half of
/// each tenant's resolved, so lookups and lists run against closed
/// history as well as open incidents.
async fn grow_history(client: &mut Client, have: u32, total: u32) {
    let per_tenant = (total - have) / TENANTS.len() as u32;
    for (index, tenant) in TENANTS.iter().enumerate() {
        let first = 1_000_000 * (index as u32 + 1) + have;
        let service = service();
        let ids = open_incidents(client, &service, tenant, first, per_tenant).await;
        let noc = operator(tenant);
        for id in ids.iter().step_by(2) {
            service
                .handle_command(
                    client,
                    &noc,
                    *id,
                    Command::ResolveIncident {
                        expected_version: 1,
                        resolution_note: None,
                    },
                    None,
                )
                .await
                .expect("committed")
                .expect("the domain accepts it");
        }
    }
}

/// Times `SAMPLES` calls of `call`, which is given the sample's index.
macro_rules! measure {
    ($report:expr, $name:expr, $i:ident => $call:expr) => {{
        let mut samples = Vec::with_capacity(SAMPLES as usize);
        for $i in 0..SAMPLES {
            let started = Instant::now();
            $call;
            samples.push(started.elapsed());
        }
        let s = stats(samples);
        writeln!(
            $report,
            "| {} | {} | {} | {} | {} |",
            $name,
            ms(s.p50),
            ms(s.p95),
            ms(s.p99),
            ms(s.max)
        )
        .unwrap();
    }};
}

async fn measure_round(client: &mut Client, history: u32, report: &mut String) {
    let tenant = TENANTS[0];
    let tenant_id = TenantId::new(tenant);
    let correlator = AuthorizationContext::correlator(tenant_id.clone());
    let noc = operator(tenant);
    let base = 10_000_000 + history;
    let service = service();

    writeln!(report, "\n### {history} incidents of history\n").unwrap();
    writeln!(report, "| Operation | p50 ms | p95 ms | p99 ms | max ms |").unwrap();
    writeln!(report, "|---|---:|---:|---:|---:|").unwrap();

    let mut opened = Vec::with_capacity(SAMPLES as usize);
    measure!(report, "Create an incident (opening event)", i => {
        let n = base + i;
        let result = service
            .ingest_detection_event(client, &correlator, &opening(&host(tenant, n), n))
            .await
            .unwrap()
            .unwrap();
        opened.push(result.incident_id.unwrap());
    });
    measure!(report, "Link an update to an open incident", i => {
        let n = base + i;
        let update = in_episode(
            event(&host(tenant, n), 2, EventKind::Updated, "p-bench", MetricKind::Bps),
            &format!("det-{n}"),
        );
        let result = service
            .ingest_detection_event(client, &correlator, &update)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.outcome_kind, IngestOutcomeKind::Updated);
    });
    measure!(report, "Refuse a duplicate event", i => {
        let n = base + i;
        let result = service
            .ingest_detection_event(client, &correlator, &opening(&host(tenant, n), n))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.outcome_kind, IngestOutcomeKind::Duplicate);
    });
    measure!(report, "Acknowledge (versioned command, idempotency key)", i => {
        let key = IdempotencyKey::new(format!("bench-ack-{history}-{i}")).unwrap();
        service
            .handle_command(
                client,
                &noc,
                opened[i as usize],
                Command::AcknowledgeIncident { expected_version: 2 },
                Some(key),
            )
            .await
            .unwrap()
            .unwrap();
    });
    measure!(report, "Replay an idempotent request", i => {
        let key = IdempotencyKey::new(format!("bench-ack-{history}-{i}")).unwrap();
        let version = service
            .handle_command(
                client,
                &noc,
                opened[i as usize],
                Command::AcknowledgeIncident { expected_version: 2 },
                Some(key),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 3);
    });
    measure!(report, "Add a note", i => {
        service
            .handle_command(
                client,
                &noc,
                opened[i as usize],
                Command::AddNote {
                    body: "benchmark note".to_string(),
                    visibility: NoteVisibility::Internal,
                },
                None,
            )
            .await
            .unwrap()
            .unwrap();
    });
    let filter = ListFilter {
        states: Vec::new(),
        severities: Vec::new(),
        priorities: Vec::new(),
        direction: None,
        target_type: None,
        incident_number: None,
        opened_between: None,
        sort: ListSort::OpenedAt,
        order: SortOrder::Desc,
        after: None,
        limit: 50,
    };
    measure!(report, "List the newest 50 incidents", _i => {
        list_incidents(client, &noc, &filter).await.unwrap().unwrap();
    });
    let open_only = ListFilter {
        states: vec!["acknowledged".to_string()],
        ..filter.clone()
    };
    measure!(report, "List 50 acknowledged incidents", _i => {
        list_incidents(client, &noc, &open_only).await.unwrap().unwrap();
    });
    measure!(report, "Read an incident's timeline", i => {
        timeline(client, &noc, &opened[i as usize], None, 100)
            .await
            .unwrap()
            .unwrap();
    });

    let platform = PlatformAuthority::from_context(&AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for("platform_admin"),
    ))
    .unwrap();
    let consumer = OutboxConsumer::new(&platform, "bench", OutboxPolicy::default());
    measure!(report, "Claim and publish an outbox batch of up to 100", _i => {
        for message in consumer.claim(&*client).await.unwrap() {
            consumer.mark_published(&*client, message.outbox_id).await.unwrap();
        }
    });
}

/// Incidents opened per second by `workers` concurrent connections, all in
/// one tenant, so they contend on its number allocator as a busy tenant
/// would.
async fn throughput(url: &str, workers: u32, report: &mut String) {
    let tenant = TENANTS[1];
    let started = Instant::now();
    let mut tasks = Vec::new();
    for worker in 0..workers {
        let url = url.to_string();
        tasks.push(tokio::spawn(async move {
            let mut client = connect(&url).await;
            let first = 20_000_000 + workers * 100_000 + worker * PER_WORKER;
            let service = service();
            open_incidents(&mut client, &service, tenant, first, PER_WORKER).await;
        }));
    }
    for task in tasks {
        task.await.expect("a worker panicked");
    }
    let elapsed = started.elapsed();
    let total = workers * PER_WORKER;
    writeln!(
        report,
        "| {workers} | {total} | {:.1} | {:.0} |",
        elapsed.as_secs_f64(),
        f64::from(total) / elapsed.as_secs_f64()
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a benchmark, not a check; run by the Benchmark workflow"]
async fn benchmark_incident_persistence() {
    let url = std::env::var(TEST_DATABASE_URL_VAR)
        .unwrap_or_else(|_| panic!("{TEST_DATABASE_URL_VAR} must name an ephemeral database"));
    let mut client = connect(&url).await;
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    wetechinetmon_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");
    let version: String = client
        .query_one("SHOW server_version", &[])
        .await
        .unwrap()
        .get(0);

    let mut report = String::new();
    writeln!(report, "## Incident persistence benchmark\n").unwrap();
    writeln!(
        report,
        "PostgreSQL {version}. {SAMPLES} sequential calls per operation on one connection; \
         latency is measured at the client."
    )
    .unwrap();

    let mut have = 0;
    for size in HISTORY_SIZES {
        let seeding = Instant::now();
        grow_history(&mut client, have, size).await;
        have = size;
        client.batch_execute("ANALYZE").await.unwrap();
        eprintln!("history of {size} built in {:.1?}", seeding.elapsed());
        measure_round(&mut client, size, &mut report).await;
    }

    writeln!(report, "\n### Concurrent incident creation, one tenant\n").unwrap();
    writeln!(report, "| Workers | Incidents | Seconds | Incidents/s |").unwrap();
    writeln!(report, "|---:|---:|---:|---:|").unwrap();
    for workers in WORKERS {
        throughput(&url, workers, &mut report).await;
    }

    println!("{report}");
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("the step summary is writable");
        file.write_all(report.as_bytes()).unwrap();
    }
}
