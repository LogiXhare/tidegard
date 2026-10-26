//! The notifier file the release tarball installs (ADR 0052) is accepted
//! as shipped, and sends nothing until an operator adds a channel.

use tidegard_notification::config::parse_file;

const NOTIFIER: &str = include_str!("../../../deployments/config/notifier.json");

#[test]
fn the_shipped_notifier_file_is_accepted_and_sends_nothing() {
    let file = parse_file(NOTIFIER).expect("notifier.json is accepted");
    assert!(file.channels.is_empty());
    assert!(file.routes.is_empty());
    assert!(file.allowed_hosts.is_empty());
}
