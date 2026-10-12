-- Phase 7A (ADR 0046): the mitigation record, separate from the incident
-- lifecycle (BQ-6).
--
-- Audit rows go to `incident_audit` and events to `incident_outbox`, both
-- polymorphic since V5 and V9, with resource and aggregate type
-- 'mitigation'. Idempotency records go to `incident_idempotency` with
-- resource type 'mitigation'.
--
-- No foreign key to `incidents`: a mitigation outlives the incident it
-- answered, and retention removes a closed incident whole.
--
-- Times are `transaction_timestamp()` (ADR 0031). `expires_at` is set
-- when a mitigation becomes active: its duration runs from the moment
-- GoBGP holds the route.
CREATE TABLE mitigations (
    mitigation_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    incident_id UUID,
    -- CIDR refuses bits set below the length, as the domain's `Prefix` does.
    prefix CIDR NOT NULL,
    action TEXT NOT NULL,
    flow_match JSONB,
    rate_bytes_per_second BIGINT,
    reason TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL,
    duplicate_key TEXT NOT NULL,
    requested_by_type TEXT NOT NULL,
    requested_by TEXT,
    approved_by_type TEXT,
    approved_by TEXT,
    dry_run BOOLEAN,
    withdrawal_cause TEXT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    approved_at TIMESTAMPTZ,
    active_since TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,

    CHECK (action IN ('rtbh', 'parent_prefix', 'flowspec_discard', 'flowspec_rate_limit')),
    CHECK (state IN (
        'proposed', 'requested', 'approved', 'announcing', 'active',
        'withdrawing', 'withdrawn', 'rejected', 'expired', 'failed'
    )),
    CHECK (version >= 1),
    CHECK (duration_seconds BETWEEN 60 AND 604800),
    CHECK (char_length(reason) BETWEEN 1 AND 1000),
    CHECK ((action IN ('flowspec_discard', 'flowspec_rate_limit')) = (flow_match IS NOT NULL)),
    CHECK ((action = 'flowspec_rate_limit') = (rate_bytes_per_second IS NOT NULL)),
    CHECK (rate_bytes_per_second IS NULL OR rate_bytes_per_second > 0),
    CHECK (action <> 'rtbh' OR masklen(prefix) = CASE family(prefix) WHEN 4 THEN 32 ELSE 128 END),
    CHECK (requested_by_type IN ('operator', 'system', 'service_account')),
    CHECK ((requested_by_type = 'system') = (requested_by IS NULL)),
    CHECK (approved_by_type IS NULL OR approved_by_type IN ('operator', 'service_account')),
    CHECK ((approved_by_type IS NULL) = (approved_by IS NULL)),
    CHECK (withdrawal_cause IS NULL OR withdrawal_cause IN ('operator', 'duration_reached', 'kill_switch'))
);

-- Duplicate-action protection (FR-6.4): one live mitigation per action,
-- prefix and match. The domain builds the key; this index enforces it
-- under concurrency.
CREATE UNIQUE INDEX mitigations_one_live_per_action
    ON mitigations (duplicate_key)
    WHERE state NOT IN ('withdrawn', 'rejected', 'expired', 'failed');

CREATE INDEX mitigations_by_tenant_created
    ON mitigations (tenant_id, created_at DESC, mitigation_id);

-- What the mitigator works on (7D).
CREATE INDEX mitigations_in_flight
    ON mitigations (state, expires_at)
    WHERE state IN ('proposed', 'requested', 'approved', 'announcing', 'active', 'withdrawing');

-- Every state change, in order. Append-only, like the incident timeline.
CREATE TABLE mitigation_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mitigation_id UUID NOT NULL REFERENCES mitigations (mitigation_id),
    tenant_id TEXT NOT NULL,
    version BIGINT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    detail TEXT,

    UNIQUE (mitigation_id, version),
    CHECK (actor_type IN ('operator', 'system', 'service_account')),
    CHECK ((actor_type = 'system') = (actor_id IS NULL))
);

GRANT SELECT, INSERT, UPDATE ON mitigations TO wetechinetmon_app;
GRANT SELECT, INSERT ON mitigation_history TO wetechinetmon_app;
GRANT USAGE, SELECT ON SEQUENCE mitigation_history_history_id_seq TO wetechinetmon_app;
