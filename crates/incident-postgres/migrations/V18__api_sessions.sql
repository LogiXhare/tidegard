-- 6C: browser sessions for the NOC UI (ADR 0043).
--
-- A session is made from an API token and lives no longer than it: the
-- foreign key removes a token's sessions with it, and every lookup also
-- checks the token is unrevoked and unexpired. Only the SHA-256 of the
-- session id is stored, as for tokens. A session ends after 30 minutes
-- idle or 12 hours in all; the API enforces both, and retention purges
-- rows past their absolute expiry.
CREATE TABLE api_sessions (
    session_hash BYTEA PRIMARY KEY,
    token_id UUID NOT NULL REFERENCES api_tokens (token_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,

    CHECK (octet_length(session_hash) = 32),
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '12 hours'),
    CHECK (last_seen_at >= created_at)
);

CREATE INDEX api_sessions_by_token ON api_sessions (token_id);
CREATE INDEX api_sessions_by_expiry ON api_sessions (expires_at);
