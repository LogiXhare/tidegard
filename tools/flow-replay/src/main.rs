//! `flow-replay` — sends synthetic IPFIX messages over UDP to a target
//! collector, for local/lab testing. See docs/security-principles.md:
//! this tool must only ever be pointed at authorized lab environments,
//! and only ever sends synthetic data (see `synthetic.rs`) — never real
//! captured traffic and never anything resembling attack traffic.
//!
//! Address convention (Phase 3, objective 11 "incoming/outgoing/
//! internal/other"): this tool doesn't know the target collector's
//! configured local prefixes, so it uses a fixed, documented convention
//! — `10.0.0.0/8` / `2001:db8::/32` as "local", `203.0.113.0/24`
//! (RFC 5737 TEST-NET-3) / `2606:4700::/32` as "external" — and expects
//! the collector under test to have `10.0.0.0/8`/`2001:db8::/32`
//! configured as a local prefix (see
//! docs/development/flow-replay.md).

mod load;
mod patterns;
mod synthetic;

use patterns::Pattern;
use std::net::{Ipv4Addr, Ipv6Addr};
use synthetic::IpProtocol;
use tokio::net::UdpSocket;

/// Data records sent per simulated second when a pattern is running.
///
/// Ten is enough that a one-second detection window sees a plausible
/// flow count rather than a single enormous record, and few enough that
/// a thirty-second run is three hundred datagrams, not thirty thousand.
const RECORDS_PER_SECOND: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Incoming,
    Outgoing,
    Internal,
    Other,
}

impl Scenario {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "incoming" => Some(Scenario::Incoming),
            "outgoing" => Some(Scenario::Outgoing),
            "internal" => Some(Scenario::Internal),
            "other" => Some(Scenario::Other),
            _ => None,
        }
    }

    /// (source, destination) IPv4 addresses for this scenario, per the
    /// module-level address convention.
    fn addrs_v4(self, i: u8) -> (Ipv4Addr, Ipv4Addr) {
        let local = Ipv4Addr::new(10, 0, 0, i % 254 + 1);
        let external_a = Ipv4Addr::new(203, 0, 113, i % 254 + 1);
        let external_b = Ipv4Addr::new(198, 51, 100, i % 254 + 1);
        match self {
            Scenario::Incoming => (external_a, local),
            Scenario::Outgoing => (local, external_a),
            Scenario::Internal => (local, Ipv4Addr::new(10, 0, 1, i % 254 + 1)),
            Scenario::Other => (external_a, external_b),
        }
    }

    fn addrs_v6(self, i: u8) -> (Ipv6Addr, Ipv6Addr) {
        let local = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16 + 1);
        let external_a = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, i as u16 + 1);
        let external_b = Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, i as u16 + 1);
        match self {
            Scenario::Incoming => (external_a, local),
            Scenario::Outgoing => (local, external_a),
            Scenario::Internal => (
                local,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, i as u16 + 1),
            ),
            Scenario::Other => (external_a, external_b),
        }
    }
}

fn parse_protocol(s: &str) -> Option<IpProtocol> {
    match s {
        "tcp" => Some(IpProtocol::Tcp),
        "udp" => Some(IpProtocol::Udp),
        "icmp" => Some(IpProtocol::Icmp),
        _ => None,
    }
}

fn print_usage() {
    eprintln!("usage: flow-replay <target_host:port> [options]");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --count N          number of data records to send (default 5)");
    eprintln!("  --scenario S       incoming | outgoing | internal | other (default incoming)");
    eprintln!("  --family F         ipv4 | ipv6 (default ipv4)");
    eprintln!("  --protocol P       tcp | udp | icmp (default tcp)");
    eprintln!(
        "  --exporters N      number of distinct observation domains to simulate (default 1)"
    );
    eprintln!(
        "  --sampling-rate N  advertise this sampling rate via an Options Template (default: none)"
    );
    eprintln!();
    eprintln!("detection-engine patterns (override --count):");
    eprintln!("  --pattern P        steady | flood | spike | flap | ramp");
    eprintln!("  --duration-secs N  how long the pattern runs (default 30)");
    eprintln!("  --peak-bps N       bits/sec the pattern peaks at (default 10000000)");
    eprintln!();
    eprintln!("rate mode, for load and soak tests (ADR 0054; overrides --count):");
    eprintln!("  --rate N           IPv4 flow records per second, 40 to a datagram");
    eprintln!("  --duration-secs N  how long to send (default 30)");
    eprintln!("  --hosts N          local hosts the records spread over (default 1000)");
    eprintln!();
    eprintln!("  A pattern varies volume over time and nothing else. Every record is the");
    eprintln!("  same synthetic, well-formed IPFIX record — no spoofing, no amplification,");
    eprintln!("  nothing resembling real attack traffic.");
    eprintln!();
    eprintln!(
        "ONLY point this at a lab/test collector you control — see docs/security-principles.md"
    );
    eprintln!("Address convention: see docs/development/flow-replay.md");
}

struct Args {
    target: String,
    count: u32,
    scenario: Scenario,
    ipv6: bool,
    protocol: IpProtocol,
    exporters: u32,
    sampling_rate: Option<u32>,
    pattern: Option<Pattern>,
    duration_secs: u64,
    peak_bps: u64,
    rate: Option<u64>,
    hosts: u32,
}

fn parse_args() -> Option<Args> {
    let mut args = std::env::args().skip(1);
    let target = args.next()?;
    let mut count = 5u32;
    let mut scenario = Scenario::Incoming;
    let mut ipv6 = false;
    let mut protocol = IpProtocol::Tcp;
    let mut exporters = 1u32;
    let mut sampling_rate = None;
    let mut pattern = None;
    let mut duration_secs = 30u64;
    let mut peak_bps = 10_000_000u64;
    let mut rate = None;
    let mut hosts = 1_000u32;

    while let Some(flag) = args.next() {
        let value = args.next()?;
        match flag.as_str() {
            "--count" => count = value.parse().ok()?,
            "--scenario" => scenario = Scenario::parse(&value)?,
            "--family" => ipv6 = value == "ipv6",
            "--protocol" => protocol = parse_protocol(&value)?,
            "--exporters" => exporters = value.parse().ok()?,
            "--sampling-rate" => sampling_rate = Some(value.parse().ok()?),
            "--pattern" => pattern = Some(Pattern::parse(&value)?),
            "--duration-secs" => duration_secs = value.parse().ok()?,
            "--peak-bps" => peak_bps = value.parse().ok()?,
            "--rate" => rate = Some(value.parse().ok()?),
            "--hosts" => hosts = value.parse().ok().filter(|n: &u32| *n > 0)?,
            _ => return None,
        }
    }

    Some(Args {
        target,
        count,
        scenario,
        ipv6,
        protocol,
        exporters,
        sampling_rate,
        pattern,
        duration_secs,
        peak_bps,
        rate,
        hosts,
    })
}

/// Sends one pattern's worth of traffic from one exporter.
///
/// Returns the sequence number to continue from, so a multi-exporter run
/// keeps each exporter's sequence coherent.
#[allow(clippy::too_many_arguments)]
async fn send_pattern(
    socket: &UdpSocket,
    args: &Args,
    pattern: Pattern,
    exporter: u32,
    observation_domain_id: u32,
    mut sequence_number: u32,
) -> std::io::Result<u32> {
    for second in 0..args.duration_secs {
        let bps = pattern.bps_at(second, args.peak_bps, args.duration_secs);
        let plans = patterns::plan_second(bps, RECORDS_PER_SECOND);
        for (index, plan) in plans.iter().enumerate() {
            let i = index as u8;
            let data = if args.ipv6 {
                let (src, dst) = args.scenario.addrs_v6(i);
                synthetic::data_message_ipv6(
                    sequence_number,
                    observation_domain_id,
                    src,
                    dst,
                    51000,
                    443,
                    args.protocol,
                    plan.bytes,
                    plan.packets,
                )
            } else {
                let (src, dst) = args.scenario.addrs_v4(i);
                synthetic::data_message_ipv4(
                    sequence_number,
                    observation_domain_id,
                    src,
                    dst,
                    51000,
                    443,
                    args.protocol,
                    plan.bytes,
                    plan.packets,
                )
            };
            socket.send(&data).await?;
            sequence_number += 1;
        }
        println!(
            "[exporter {exporter}] second {}/{}: {} records at {} bps",
            second + 1,
            args.duration_secs,
            plans.len(),
            bps
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(sequence_number)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let Some(args) = parse_args() else {
        print_usage();
        std::process::exit(2);
    };

    if let Some(pattern) = args.pattern {
        println!(
            "pattern {}: {}s at up to {} bps — expect: {}",
            pattern.as_str(),
            args.duration_secs,
            args.peak_bps,
            pattern.expectation()
        );
    }

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&args.target).await?;

    if let Some(rate) = args.rate {
        if args.exporters != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--rate sends from one observation domain; --exporters does not apply",
            ));
        }
        // One line a script can read: what was sent, and how fast.
        let report = load::run(
            &socket,
            1,
            rate,
            std::time::Duration::from_secs(args.duration_secs),
            args.hosts,
        )
        .await?;
        let seconds = report.elapsed.as_secs_f64();
        println!(
            "load: sent {} records in {} datagrams over {:.3} s ({:.0} records/s)",
            report.records,
            report.datagrams,
            seconds,
            report.records as f64 / seconds
        );
        return Ok(());
    }

    for exporter in 0..args.exporters {
        let observation_domain_id = exporter + 1;
        let mut sequence_number = 1u32;

        if let Some(rate) = args.sampling_rate {
            let opt_tmpl =
                synthetic::options_template_message(sequence_number, observation_domain_id);
            socket.send(&opt_tmpl).await?;
            sequence_number += 1;
            let opt_data =
                synthetic::options_data_message(sequence_number, observation_domain_id, 1, rate);
            socket.send(&opt_data).await?;
            sequence_number += 1;
            println!("[exporter {exporter}] sent sampling options (rate={rate}) for observation domain {observation_domain_id}");
        }

        let template = if args.ipv6 {
            synthetic::template_message_ipv6(sequence_number, observation_domain_id)
        } else {
            synthetic::template_message_ipv4(sequence_number, observation_domain_id)
        };
        socket.send(&template).await?;
        sequence_number += 1;
        println!("[exporter {exporter}] sent template message (observation_domain_id={observation_domain_id})");

        if let Some(pattern) = args.pattern {
            sequence_number = send_pattern(
                &socket,
                &args,
                pattern,
                exporter,
                observation_domain_id,
                sequence_number,
            )
            .await?;
            let _ = sequence_number;
            continue;
        }

        for i in 0..args.count {
            let packets = 10 + i as u64;
            let bytes = 1000 + i as u64 * 100;
            let data = if args.ipv6 {
                let (src, dst) = args.scenario.addrs_v6(i as u8);
                synthetic::data_message_ipv6(
                    sequence_number,
                    observation_domain_id,
                    src,
                    dst,
                    51000,
                    443,
                    args.protocol,
                    bytes,
                    packets,
                )
            } else {
                let (src, dst) = args.scenario.addrs_v4(i as u8);
                synthetic::data_message_ipv4(
                    sequence_number,
                    observation_domain_id,
                    src,
                    dst,
                    51000,
                    443,
                    args.protocol,
                    bytes,
                    packets,
                )
            };
            socket.send(&data).await?;
            println!(
                "[exporter {exporter}] sent data record {}/{} ({:?}, {:?})",
                i + 1,
                args.count,
                args.scenario,
                args.protocol
            );
            sequence_number += 1;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    match args.pattern {
        Some(pattern) => println!(
            "done — sent the {} pattern from {} exporter(s) to {}; expect: {}",
            pattern.as_str(),
            args.exporters,
            args.target,
            pattern.expectation()
        ),
        None => println!(
            "done — sent traffic from {} exporter(s) to {}",
            args.exporters, args.target
        ),
    }
    Ok(())
}
