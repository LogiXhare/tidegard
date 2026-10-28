-- Phase 8A-2 (ADR 0060): a token's scope, and the roles of FR-12.2.
--
-- A token is scoped to one tenant, as every token was until now, or to
-- the platform. A platform token carries one of the provider roles
-- (BQ-21), names no tenant (it chooses the tenant it acts in per request),
-- and lives at most 90 days. A tenant token can never carry a provider
-- role, and a platform token never a tenant role: the database refuses
-- both, whatever the application does.
ALTER TABLE api_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'tenant';
ALTER TABLE api_tokens ALTER COLUMN tenant_id DROP NOT NULL;

-- V15's list of the four v1.0.0 roles gives way to one per scope.
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scope_and_role CHECK (
    (
        scope = 'tenant'
        AND tenant_id IS NOT NULL
        AND role IN (
            'viewer', 'operator', 'senior_operator', 'noc_lead',
            'customer_admin', 'security_analyst', 'automation'
        )
    )
    OR (
        scope = 'platform'
        AND tenant_id IS NULL
        AND role IN ('noc_operator', 'noc_admin', 'auditor', 'platform_admin', 'super_admin')
        AND expires_at <= created_at + interval '90 days'
    )
);

-- `automation` is for integrations, never a person.
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_automation_is_a_service CHECK (
    role <> 'automation' OR actor_type = 'service_account'
);

CREATE INDEX api_tokens_platform ON api_tokens (created_at) WHERE scope = 'platform';
