-- Portal users persisted on first successful OAuth2 login.
-- One row per (provider, provider_subject) pair — i.e. one row per Google account.
-- email is unique across all providers; if the same email comes back from a
-- different provider that's treated as a new account intentionally.

CREATE TABLE users (
    id                 UUID PRIMARY KEY,
    email              VARCHAR(320) NOT NULL,
    name               VARCHAR(255),
    picture_url        VARCHAR(1024),
    email_verified     BOOLEAN NOT NULL DEFAULT FALSE,
    provider           VARCHAR(64) NOT NULL,
    provider_subject   VARCHAR(255) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    login_count        INT NOT NULL DEFAULT 1,

    CONSTRAINT users_provider_subject_uk UNIQUE (provider, provider_subject)
);

CREATE INDEX users_email_idx ON users (email);
CREATE INDEX users_last_login_idx ON users (last_login_at DESC);

COMMENT ON TABLE users IS 'Portal users created on first Google OAuth2 login. Sign-in is gated by app.auth.enabled.';
COMMENT ON COLUMN users.provider_subject IS 'The provider-issued subject (e.g. Google sub claim). Together with provider it uniquely identifies an account.';
COMMENT ON COLUMN users.login_count IS 'Cumulative successful logins; incremented on each upsert.';
