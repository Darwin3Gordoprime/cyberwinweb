ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_data TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS banner_data TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS banner_color CHAR(7) NOT NULL DEFAULT '#1c1917';

ALTER TABLE creators
    ADD COLUMN IF NOT EXISTS is_live BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS friend_requests (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    requester_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    recipient_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT friend_requests_distinct_users CHECK (requester_uid <> recipient_uid)
);

CREATE UNIQUE INDEX IF NOT EXISTS friend_requests_user_pair_idx
    ON friend_requests (LEAST(requester_uid, recipient_uid), GREATEST(requester_uid, recipient_uid));
CREATE INDEX IF NOT EXISTS friend_requests_recipient_status_idx
    ON friend_requests (recipient_uid, status, created_at DESC);

CREATE TABLE IF NOT EXISTS direct_messages (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sender_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    recipient_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    message TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT direct_messages_distinct_users CHECK (sender_uid <> recipient_uid)
);

CREATE INDEX IF NOT EXISTS direct_messages_conversation_idx
    ON direct_messages (sender_uid, recipient_uid, created_at DESC);
