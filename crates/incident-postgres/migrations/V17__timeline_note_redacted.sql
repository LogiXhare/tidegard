-- 5F: note redaction (FU-63) adds the `note_redacted` timeline entry.
--
-- V4's entry_type CHECK lists every implemented type and reserves the
-- planned ones; `note_superseded` was reserved there, `note_redacted`
-- was not. V4 is applied and checksummed, so the constraint is replaced
-- here rather than edited in place. Added NOT VALID and then validated,
-- so existing rows are checked without holding the strongest lock for
-- the scan.
ALTER TABLE incident_timeline DROP CONSTRAINT incident_timeline_entry_type_check;

ALTER TABLE incident_timeline ADD CONSTRAINT incident_timeline_entry_type_check
    CHECK (entry_type IN (
        -- Implemented today (crates/incident/src/timeline.rs).
        'opened', 'event_linked', 'late_event_linked', 'duplicate_ignored',
        'state_changed', 'category_changed', 'severity_changed',
        'priority_changed', 'assignment_changed', 'note_added',
        'note_superseded', 'note_redacted',
        'suppressed', 'unsuppressed', 'reopened', 'limit_reached',
        'tag_added', 'tag_removed',
        -- Reserved, not yet implemented (incident-persistence.md).
        'evidence_added', 'recovery_detected',
        'recovery_aborted', 'resolved', 'closed', 'correlation_decision',
        'persistence_retry', 'notification_result', 'mitigation_result'
    )) NOT VALID;

ALTER TABLE incident_timeline VALIDATE CONSTRAINT incident_timeline_entry_type_check;
