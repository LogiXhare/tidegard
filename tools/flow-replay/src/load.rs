//! Rate mode (ADR 0054): a fixed number of flow records a second, for
//! the 9B load and soak tests. Synthetic only, as everything here: the
//! addresses are the documented lab convention and the counters are
//! constants.
//!
//! Records go out 40 to a datagram, about 1.2 KB, as a busy exporter
//! batches them. The sender paces itself against the clock: every few
//! milliseconds it sends what is due since the start, so a slow moment is
//! made up rather than lost, and the rate it reports is the rate it sent.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::synthetic::{self, IpProtocol, Ipv4Record};

/// Records per datagram: 16 + 4 + 40 × 29 = 1,180 bytes, under any MTU.
pub const RECORDS_PER_DATAGRAM: usize = 40;
const PACING: Duration = Duration::from_millis(2);

/// The `index`-th of `hosts` local hosts, in `10.0.0.0/8`: 10.0.x.y with
/// y from 1 to 250, so no address ends in 0 or 255.
pub fn local_host(index: u32) -> Ipv4Addr {
    let block = index / 250;
    Ipv4Addr::new(
        10,
        (block / 256) as u8,
        (block % 256) as u8,
        (index % 250 + 1) as u8,
    )
}

/// The `index`-th remote peer, in TEST-NET-3 (`203.0.113.0/24`).
pub fn remote_host(index: u32) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, (index % 50 + 1) as u8)
}

/// One record, incoming to a local host from a remote one.
fn record(n: u64, hosts: u32) -> Ipv4Record {
    Ipv4Record {
        source: remote_host((n % 50) as u32),
        destination: local_host((n % u64::from(hosts.max(1))) as u32),
        source_port: 40_000 + (n % 20_000) as u16,
        destination_port: 443,
        protocol: if n.is_multiple_of(4) {
            IpProtocol::Udp
        } else {
            IpProtocol::Tcp
        },
        byte_count: 15_000,
        packet_count: 10,
    }
}

/// What a run sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadReport {
    pub records: u64,
    pub datagrams: u64,
    pub elapsed: Duration,
}

/// The records due after `elapsed` at `rate` a second.
pub fn due(rate: u64, elapsed: Duration) -> u64 {
    (u128::from(rate) * elapsed.as_nanos() / 1_000_000_000) as u64
}

/// Sends `rate` records a second for `duration`, from one observation
/// domain, after its template. Returns what it sent.
pub async fn run(
    socket: &UdpSocket,
    observation_domain_id: u32,
    rate: u64,
    duration: Duration,
    hosts: u32,
) -> std::io::Result<LoadReport> {
    let mut sequence_number = 0u32;
    socket
        .send(&synthetic::template_message_ipv4(
            sequence_number,
            observation_domain_id,
        ))
        .await?;
    let start = Instant::now();
    let mut sent = 0u64;
    let mut datagrams = 0u64;
    let mut batch = Vec::with_capacity(RECORDS_PER_DATAGRAM);
    loop {
        let elapsed = start.elapsed();
        if elapsed >= duration {
            break;
        }
        let target = due(rate, elapsed);
        while sent < target {
            batch.clear();
            let count = (target - sent).min(RECORDS_PER_DATAGRAM as u64);
            for n in sent..sent + count {
                batch.push(record(n, hosts));
            }
            socket
                .send(&synthetic::data_message_ipv4_batch(
                    sequence_number,
                    observation_domain_id,
                    &batch,
                ))
                .await?;
            sent += count;
            datagrams += 1;
            sequence_number = sequence_number.wrapping_add(count as u32);
        }
        tokio::time::sleep(PACING).await;
    }
    Ok(LoadReport {
        records: sent,
        datagrams,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_stay_inside_the_lab_ranges() {
        assert_eq!(local_host(0), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(local_host(249), Ipv4Addr::new(10, 0, 0, 250));
        assert_eq!(local_host(250), Ipv4Addr::new(10, 0, 1, 1));
        assert_eq!(local_host(999), Ipv4Addr::new(10, 0, 3, 250));
        for i in 0..200 {
            let remote = remote_host(i);
            assert_eq!(&remote.octets()[..3], &[203, 0, 113]);
            assert!(remote.octets()[3] >= 1 && remote.octets()[3] <= 50);
        }
    }

    #[test]
    fn the_schedule_is_exact() {
        assert_eq!(due(100_000, Duration::from_secs(60)), 6_000_000);
        assert_eq!(due(100_000, Duration::from_millis(15)), 1_500);
        assert_eq!(due(0, Duration::from_secs(5)), 0);
    }

    #[test]
    fn a_full_datagram_fits_any_mtu() {
        let records: Vec<_> = (0..RECORDS_PER_DATAGRAM as u64)
            .map(|n| record(n, 1_000))
            .collect();
        let message = synthetic::data_message_ipv4_batch(0, 1, &records);
        assert_eq!(
            message.len(),
            16 + 4 + RECORDS_PER_DATAGRAM * synthetic::IPV4_RECORD_LEN
        );
        assert!(message.len() <= 1_400);
    }

    #[tokio::test]
    async fn sends_what_it_reports() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .connect(receiver.local_addr().unwrap())
            .await
            .unwrap();
        // Count while sending: a socket buffer may drop what nobody reads.
        let counter = tokio::spawn(async move {
            let mut buf = vec![0u8; 2_048];
            let mut datagrams = 0u64;
            while let Ok(Ok((len, _))) =
                tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf)).await
            {
                assert!(len > 16);
                datagrams += 1;
            }
            datagrams
        });
        let report = run(&sender, 1, 20_000, Duration::from_millis(200), 100)
            .await
            .unwrap();
        // About 4,000 records in 200 ms, give or take a pacing tick.
        assert!(
            report.records >= 3_500 && report.records <= 4_100,
            "{report:?}"
        );
        assert!(report.datagrams >= report.records / RECORDS_PER_DATAGRAM as u64);
        let received = counter.await.unwrap();
        // The template plus the data sets, all of them on loopback.
        assert!(
            received >= 1 && received <= report.datagrams + 1,
            "{received}"
        );
    }
}
