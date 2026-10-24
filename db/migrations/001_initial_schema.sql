CREATE TABLE IF NOT EXISTS users (
    firebase_uid TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    nickname VARCHAR(20) NOT NULL DEFAULT '',
    player_tag VARCHAR(11) NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player', 'admin')),
    theme_key TEXT NOT NULL DEFAULT 'red',
    accent_color CHAR(7) NOT NULL DEFAULT '#dc2626',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS announcements (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title VARCHAR(80) NOT NULL,
    message VARCHAR(500) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL REFERENCES users(firebase_uid),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS creators (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    handle VARCHAR(40) NOT NULL UNIQUE,
    display_name VARCHAR(80) NOT NULL,
    category VARCHAR(40) NOT NULL DEFAULT 'Creador Oficial',
    profile_url TEXT NOT NULL,
    live_url TEXT,
    approved BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL REFERENCES users(firebase_uid),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT creators_profile_url_http CHECK (profile_url ~ '^https?://'),
    CONSTRAINT creators_live_url_http CHECK (live_url IS NULL OR live_url ~ '^https?://')
);

CREATE INDEX IF NOT EXISTS announcements_active_created_idx ON announcements (active, created_at DESC);
CREATE INDEX IF NOT EXISTS creators_approved_created_idx ON creators (approved, created_at DESC);
