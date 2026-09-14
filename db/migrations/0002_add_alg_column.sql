-- Add alg column to webauthn_credentials (needed by the native WebAuthn worker)
-- Apply to the real DB:
--   wrangler d1 execute masshealth-crm-db --remote --file=db/migrations/0002_add_alg_column.sql

ALTER TABLE webauthn_credentials ADD COLUMN alg TEXT NOT NULL DEFAULT 'ES256';
