-- Phase 7D (ADR 0049): the runtime kill switch, and the exact route each
-- mitigation announced.
--
-- `mitigation_controls` has exactly one row. The kill switch is
-- deployment-wide: while it is on, the safety guard refuses every new
-- mitigation at every moment it runs (ADR 0047), and the mitigator takes
-- down whatever is up. Turning it on is a `noc_lead` action; turning it
-- off is a platform administrator's. Both are audited.
CREATE TABLE mitigation_controls (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    kill_switch BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    changed_at TIMESTAMPTZ,
    changed_by_type TEXT,
    changed_by TEXT,
    reason TEXT,

    CHECK (singleton),
    CHECK (version >= 1),
    CHECK (changed_by_type IS NULL OR changed_by_type IN ('operator', 'service_account')),
    CHECK (reason IS NULL OR char_length(reason) BETWEEN 1 AND 1000)
);

INSERT INTO mitigation_controls (singleton) VALUES (TRUE);

-- The route the mitigator built when announcing began, dry-run or not:
-- the evidence of exactly what was, or would have been, announced.
ALTER TABLE mitigations ADD COLUMN route JSONB;

GRANT SELECT, UPDATE ON mitigation_controls TO wetechinetmon_app;
