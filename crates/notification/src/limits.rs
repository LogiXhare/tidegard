//! Storm control (ADR 0045, R24): a channel hears about the same event for
//! the same incident once per window, and at most so many messages a
//! minute. Both live in memory and are bounded: a restart forgets them,
//! and may resend once.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Remembered sends, at most this many before the oldest are forgotten.
const DEDUP_MAX_ENTRIES: usize = 100_000;

#[derive(Debug)]
pub struct Dedup {
    window: Duration,
    seen: HashMap<(String, String, String), Instant>,
}

impl Dedup {
    pub fn new(window: Duration) -> Self {
        Dedup {
            window,
            seen: HashMap::new(),
        }
    }

    /// Whether `channel` has already had `event` for `incident` within the
    /// window. Does not record anything: call [`Dedup::record`] once the
    /// message is delivered.
    pub fn is_duplicate(&self, channel: &str, incident: &str, event: &str, now: Instant) -> bool {
        self.seen
            .get(&(channel.to_string(), incident.to_string(), event.to_string()))
            .is_some_and(|sent| now.duration_since(*sent) < self.window)
    }

    pub fn record(&mut self, channel: &str, incident: &str, event: &str, now: Instant) {
        if self.seen.len() >= DEDUP_MAX_ENTRIES {
            let window = self.window;
            self.seen
                .retain(|_, sent| now.duration_since(*sent) < window);
            if self.seen.len() >= DEDUP_MAX_ENTRIES {
                self.seen.clear();
            }
        }
        self.seen.insert(
            (channel.to_string(), incident.to_string(), event.to_string()),
            now,
        );
    }
}

/// A token bucket per channel: `per_minute` messages, refilled evenly.
#[derive(Debug)]
pub struct RateLimit {
    per_minute: u32,
    buckets: HashMap<String, (f64, Instant)>,
}

impl RateLimit {
    pub fn new(per_minute: u32) -> Self {
        RateLimit {
            per_minute: per_minute.max(1),
            buckets: HashMap::new(),
        }
    }

    /// Takes one message's worth from `channel`'s bucket, if there is one.
    pub fn take(&mut self, channel: &str, now: Instant) -> bool {
        let capacity = f64::from(self.per_minute);
        let per_second = capacity / 60.0;
        let (tokens, last) = self
            .buckets
            .entry(channel.to_string())
            .or_insert((capacity, now));
        let refilled =
            (*tokens + now.duration_since(*last).as_secs_f64() * per_second).min(capacity);
        *last = now;
        if refilled >= 1.0 {
            *tokens = refilled - 1.0;
            true
        } else {
            *tokens = refilled;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duplicate_is_held_back_for_the_window_only() {
        let start = Instant::now();
        let mut dedup = Dedup::new(Duration::from_secs(300));
        assert!(!dedup.is_duplicate("slack", "i1", "incident.opened", start));
        dedup.record("slack", "i1", "incident.opened", start);
        let soon = start + Duration::from_secs(60);
        assert!(dedup.is_duplicate("slack", "i1", "incident.opened", soon));
        assert!(
            !dedup.is_duplicate("teams", "i1", "incident.opened", soon),
            "per channel"
        );
        assert!(
            !dedup.is_duplicate("slack", "i2", "incident.opened", soon),
            "per incident"
        );
        assert!(
            !dedup.is_duplicate("slack", "i1", "incident.resolved", soon),
            "per event"
        );
        assert!(!dedup.is_duplicate(
            "slack",
            "i1",
            "incident.opened",
            start + Duration::from_secs(301)
        ));
    }

    #[test]
    fn a_burst_is_cut_at_the_limit_and_refills() {
        let start = Instant::now();
        let mut limit = RateLimit::new(30);
        let sent = (0..100).filter(|_| limit.take("slack", start)).count();
        assert_eq!(sent, 30, "a burst of 100 sends 30");
        assert!(
            limit.take("teams", start),
            "each channel has its own bucket"
        );
        assert!(!limit.take("slack", start + Duration::from_secs(1)));
        assert!(
            limit.take("slack", start + Duration::from_secs(2)),
            "one every two seconds"
        );
    }
}
