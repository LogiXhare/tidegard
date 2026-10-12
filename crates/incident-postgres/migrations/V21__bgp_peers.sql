-- Phase 7E (ADR 0050): GoBGP's peers as the mitigator last saw them.
--
-- The API never talks to GoBGP; only the mitigator does (ADR 0048). So
-- the mitigator writes what it sees here at every reconciliation, and the
-- API reads it. `updated_at` says how fresh it is: a mitigator that has
-- stopped leaves an old snapshot, never a false "established".
CREATE TABLE bgp_peers (
    neighbor_address TEXT PRIMARY KEY,
    peer_asn BIGINT NOT NULL,
    session_state TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),

    CHECK (peer_asn BETWEEN 0 AND 4294967295),
    CHECK (session_state IN (
        'unknown', 'idle', 'connect', 'active', 'opensent', 'openconfirm', 'established'
    ))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON bgp_peers TO wetechinetmon_app;
