-- Phase 8A (ADR 0060): the tenant registry and prefix ownership (BQ-20).
--
-- Until now a tenant was only an id carried by tokens and records. This
-- table makes each one a row with a status, and `tenant_prefixes` records
-- which addresses it owns. Every service reads ownership from here.
--
-- `platform` is not a tenant: it is the scope of deployment-wide events
-- (BGP sessions, ADR 0050) and of the provider roles to come.
CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),

    CHECK (char_length(tenant_id) BETWEEN 1 AND 128),
    CHECK (tenant_id <> 'platform'),
    CHECK (char_length(display_name) BETWEEN 1 AND 200),
    CHECK (status IN ('active', 'suspended')),
    CHECK (updated_at >= created_at)
);

-- An upgraded install finds every tenant it already has registered and
-- active, named by its id: every tenant id on every table that carries
-- one, so a table added later cannot be missed by a hand-kept list.
DO $$
DECLARE
    source TEXT;
BEGIN
    FOR source IN
        SELECT table_name FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND column_name = 'tenant_id'
          AND table_name <> 'tenants'
    LOOP
        EXECUTE format(
            'INSERT INTO tenants (tenant_id, display_name)
             SELECT DISTINCT tenant_id, tenant_id FROM %I
             WHERE tenant_id <> %L
             ON CONFLICT (tenant_id) DO NOTHING',
            source, 'platform'
        );
    END LOOP;
END
$$;

-- A prefix belongs to exactly one tenant, and no two rows overlap, in any
-- tenant: the exclusion constraint makes an overlapping claim impossible
-- in the database, not only in code. A claim no wider than /8 or /16
-- keeps one mistaken row from swallowing everyone's traffic.
CREATE TABLE tenant_prefixes (
    prefix CIDR PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),

    CONSTRAINT tenant_prefixes_no_overlap EXCLUDE USING gist (prefix inet_ops WITH &&),
    CHECK (
        (family(prefix) = 4 AND masklen(prefix) >= 8)
        OR (family(prefix) = 6 AND masklen(prefix) >= 16)
    )
);

CREATE INDEX tenant_prefixes_by_tenant ON tenant_prefixes (tenant_id, prefix);

-- A token names a registered tenant, so a typo cannot mint a token for a
-- tenant nobody knows of.
ALTER TABLE api_tokens
    ADD CONSTRAINT api_tokens_tenant_registered
    FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id);

GRANT SELECT, INSERT, UPDATE ON tenants TO wetechinetmon_app;
GRANT SELECT, INSERT, DELETE ON tenant_prefixes TO wetechinetmon_app;
