-- MassHealth CRM — D1 schema
-- Reverse-engineered from worker/index.js queries.
-- Apply via: wrangler d1 execute masshealth-crm-db --remote --file=db/schema.sql

CREATE TABLE IF NOT EXISTS facilities (
  id                INTEGER PRIMARY KEY,
  name              TEXT NOT NULL DEFAULT '',
  npi               TEXT,
  city              TEXT,
  state             TEXT DEFAULT 'MA',
  masshealth_policy TEXT NOT NULL DEFAULT 'UNKNOWN',  -- YES | CASE_BY_CASE | NO | UNKNOWN
  bed_availability  TEXT NOT NULL DEFAULT 'UNKNOWN',  -- YES | WAITLIST | NO | UNKNOWN
  referral_status   TEXT NOT NULL DEFAULT 'NOT_STARTED',
  disqualified      INTEGER NOT NULL DEFAULT 0,        -- 0 | 1
  data_blob         TEXT,                              -- full facility JSON
  updated_at        TEXT
);

CREATE TABLE IF NOT EXISTS patients (
  id              TEXT PRIMARY KEY,           -- slug, e.g. "case-interstate"
  name            TEXT NOT NULL DEFAULT '',
  gender          TEXT,
  target_region   TEXT,
  placement_stage TEXT NOT NULL DEFAULT 'GATHERING_INFO',
  data_blob       TEXT,                       -- full patient JSON
  updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS call_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  facility_id  INTEGER NOT NULL REFERENCES facilities(id),
  patient_id   TEXT REFERENCES patients(id),
  timestamp    TEXT,
  contact_name TEXT,
  notes        TEXT,
  outcome      TEXT
);

CREATE TABLE IF NOT EXISTS progress_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id TEXT REFERENCES patients(id),
  facility_id INTEGER REFERENCES facilities(id),
  event_type TEXT NOT NULL,  -- STAGE_CHANGE | CALL_LOGGED | EMAIL_SENT | EMAIL_OUTCOME
  old_value  TEXT,
  new_value  TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repatriation_progress (
  patient_id   TEXT NOT NULL REFERENCES patients(id),
  stage        INTEGER NOT NULL,   -- 1–7
  status       TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING | COMPLETE
  notes        TEXT,
  completed_at TEXT,
  updated_at   TEXT,
  UNIQUE(patient_id, stage)
);

CREATE TABLE IF NOT EXISTS email_outreach (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  facility_id          INTEGER NOT NULL REFERENCES facilities(id),
  patient_id           TEXT REFERENCES patients(id),
  decision_maker_name  TEXT,
  decision_maker_role  TEXT,
  to_email             TEXT NOT NULL,
  subject              TEXT,
  body                 TEXT,
  sent_at              TEXT,
  follow_up_date       TEXT,
  response_received    INTEGER NOT NULL DEFAULT 0,  -- 0 | 1
  response_date        TEXT,
  outcome_status       TEXT   -- NO_RESPONSE | DECLINED | PENDING_REVIEW | ACCEPTED | etc.
);
