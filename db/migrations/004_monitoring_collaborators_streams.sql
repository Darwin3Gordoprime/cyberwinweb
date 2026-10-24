ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

ALTER TABLE creators
    ADD COLUMN IF NOT EXISTS firebase_uid TEXT REFERENCES users(firebase_uid) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS bio VARCHAR(500) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS social_links JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS featured BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS creators_firebase_uid_idx
    ON creators (firebase_uid) WHERE firebase_uid IS NOT NULL;

CREATE TABLE IF NOT EXISTS creator_streams (
    creator_uid TEXT PRIMARY KEY REFERENCES users(firebase_uid) ON DELETE CASCADE,
    creator_id BIGINT NOT NULL UNIQUE REFERENCES creators(id) ON DELETE CASCADE,
    mux_live_stream_id TEXT NOT NULL UNIQUE,
    stream_key_encrypted TEXT NOT NULL,
    playback_id TEXT NOT NULL,
    title VARCHAR(120) NOT NULL DEFAULT 'Cyber Win en vivo',
    status TEXT NOT NULL DEFAULT 'idle',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stream_assets (
    mux_asset_id TEXT PRIMARY KEY,
    creator_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    creator_nickname VARCHAR(20) NOT NULL DEFAULT '',
    title VARCHAR(120) NOT NULL DEFAULT 'Retransmisión Cyber Win',
    playback_id TEXT,
    status TEXT NOT NULL DEFAULT 'preparing',
    duration_seconds DOUBLE PRECISION,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS stream_assets_created_idx ON stream_assets (created_at DESC);
CREATE INDEX IF NOT EXISTS stream_assets_public_idx ON stream_assets (status, created_at DESC);
