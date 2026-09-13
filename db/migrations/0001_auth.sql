-- Passkey / session auth tables
-- Apply to the real DB (never the demo DB):
--   wrangler d1 execute masshealth-crm-db --remote --file=db/migrations/0001_auth.sql

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id          TEXT PRIMARY KEY,               -- base64url credential id
  user_id     TEXT NOT NULL DEFAULT 'asia',
  public_key  TEXT NOT NULL,                  -- base64url-encoded COSE public key (Uint8Array)
  sign_count  INTEGER NOT NULL DEFAULT 0,
  transports  TEXT,                           -- JSON array of transport hints
  created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,               -- 32-byte random token, base64url
  user_id    TEXT NOT NULL DEFAULT 'asia',
  expires_at TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS challenges (
  id         TEXT PRIMARY KEY,               -- base64url challenge value
  type       TEXT NOT NULL,                  -- 'registration' | 'authentication'
  origin     TEXT,                           -- frontend origin that started this flow
  created_at TEXT DEFAULT (datetime('now'))
);
