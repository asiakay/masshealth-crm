-- Demo seed data for masshealth-crm-demo-db
-- Synthetic fixtures only — follows CONTRIBUTING.md naming rules (first name + last initial).
-- Apply after schema:
--   wrangler d1 execute masshealth-crm-demo-db --remote --file=db/schema.sql
--   wrangler d1 execute masshealth-crm-demo-db --remote --file=db/seed-demo.sql

INSERT INTO facilities (id, name, city, state, masshealth_policy, bed_availability, referral_status, data_blob, updated_at)
VALUES
  (1, 'Sunrise Care Center (DEMO)', 'Springfield', 'MA', 'YES', 'YES', 'PENDING',
   '{"id":1,"facility_name":"Sunrise Care Center (DEMO)","city":"Springfield","state":"MA","masshealth_policy":"YES","bed_availability":"YES","referral_status":"PENDING"}',
   datetime('now')),
  (2, 'Harbor View Rehabilitation (DEMO)', 'Boston', 'MA', 'CASE_BY_CASE', 'WAITLIST', 'IN_PROGRESS',
   '{"id":2,"facility_name":"Harbor View Rehabilitation (DEMO)","city":"Boston","state":"MA","masshealth_policy":"CASE_BY_CASE","bed_availability":"WAITLIST","referral_status":"IN_PROGRESS"}',
   datetime('now')),
  (3, 'Maple Ridge Health Center (DEMO)', 'Worcester', 'MA', 'YES', 'NO', 'PENDING',
   '{"id":3,"facility_name":"Maple Ridge Health Center (DEMO)","city":"Worcester","state":"MA","masshealth_policy":"YES","bed_availability":"NO","referral_status":"PENDING"}',
   datetime('now'));

INSERT INTO patients (id, name, gender, target_region, placement_stage, data_blob, updated_at)
VALUES
  ('demo-arthur-v', 'Arthur V.', 'M', 'Greater Boston', 'ACTIVE_REFERRAL',
   '{"id":"demo-arthur-v","name":"Arthur V.","gender":"M","target_region":"Greater Boston","placement_stage":"ACTIVE_REFERRAL"}',
   datetime('now')),
  ('demo-eleanor-v', 'Eleanor V.', 'F', 'Central MA', 'GATHERING_INFO',
   '{"id":"demo-eleanor-v","name":"Eleanor V.","gender":"F","target_region":"Central MA","placement_stage":"GATHERING_INFO"}',
   datetime('now')),
  ('demo-thomas-g', 'Thomas G.', 'M', 'Western MA', 'PLACEMENT_CONFIRMED',
   '{"id":"demo-thomas-g","name":"Thomas G.","gender":"M","target_region":"Western MA","placement_stage":"PLACEMENT_CONFIRMED"}',
   datetime('now'));

INSERT INTO progress_events (patient_id, facility_id, event_type, old_value, new_value)
VALUES
  ('demo-arthur-v', 1, 'STAGE_CHANGE', 'GATHERING_INFO', 'ACTIVE_REFERRAL'),
  ('demo-eleanor-v', 2, 'CALL_LOGGED', NULL, 'Initial inquiry placed — awaiting admissions callback'),
  ('demo-thomas-g', 1, 'STAGE_CHANGE', 'ACTIVE_REFERRAL', 'PLACEMENT_CONFIRMED');
