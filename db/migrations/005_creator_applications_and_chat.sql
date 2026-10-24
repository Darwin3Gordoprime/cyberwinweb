ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users
    ADD CONSTRAINT users_role_check CHECK (role IN ('player', 'creator', 'admin'));

CREATE TABLE IF NOT EXISTS creator_applications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    applicant_uid TEXT NOT NULL REFERENCES users(firebase_uid) ON DELETE CASCADE,
    social_handle VARCHAR(40) NOT NULL,
    display_name VARCHAR(80) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT REFERENCES users(firebase_uid) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS creator_applications_one_pending_per_user_idx
    ON creator_applications (applicant_uid) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS creator_applications_pending_idx
    ON creator_applications (submitted_at DESC) WHERE status = 'pending';

INSERT INTO creator_applications (applicant_uid, social_handle, display_name)
SELECT DISTINCT ON (applicant.firebase_uid)
       applicant.firebase_uid,
       LOWER(application.value->>'usuario'),
       LEFT(COALESCE(NULLIF(application.value->>'nombre', ''), NULLIF(applicant.nickname, ''),
                     split_part(applicant.email, '@', 1), 'Creador'), 80)
FROM app_state AS state
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(state.value) = 'array' THEN state.value ELSE '[]'::jsonb END
) AS application(value)
JOIN users AS applicant ON applicant.firebase_uid = application.value->>'firebaseUid'
WHERE state.state_key = 'creator-applications'
  AND application.value->>'estado' = 'PENDIENTE'
  AND application.value->>'usuario' ~* '^[a-z0-9._]{2,40}$'
  AND NOT EXISTS (
      SELECT 1 FROM creator_applications existing
      WHERE existing.applicant_uid = applicant.firebase_uid AND existing.status = 'pending'
  )
ORDER BY applicant.firebase_uid, application.value->>'submittedAt' DESC NULLS LAST;

ALTER TABLE direct_messages
    ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS direct_messages_unread_idx
    ON direct_messages (recipient_uid, sender_uid, created_at DESC) WHERE read_at IS NULL;
