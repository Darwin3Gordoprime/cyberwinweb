CREATE TABLE IF NOT EXISTS app_state (
    state_key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO app_state (state_key, value)
VALUES
    ('events', '[]'::jsonb),
    ('proposals', '[]'::jsonb),
    ('bugs', '[]'::jsonb),
    ('creator-applications', '[]'::jsonb),
    ('public-settings', '{}'::jsonb)
ON CONFLICT (state_key) DO NOTHING;
