const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Map in-app facility fields → D1 structured columns (for queryability)
function facilityMeta(f) {
  return {
    id: f.id,
    name: f.facility_name ?? f.name ?? '',
    npi: f.npi ?? null,
    city: f.city ?? null,
    state: f.state ?? 'MA',
    masshealth_policy: f.accepts_mh_pending ?? f.masshealth_policy ?? 'UNKNOWN',
    bed_availability: f.current_bed_available ?? f.bed_availability ?? 'UNKNOWN',
    referral_status: f.referral_status ?? 'NOT_STARTED',
    disqualified: f.disqualified ? 1 : 0,
  };
}

function patientMeta(p) {
  return {
    id: p.id,
    name: p.name ?? '',
    gender: p.gender ?? null,
    target_region: p.target_region ?? null,
    placement_stage: p.placement_stage ?? 'GATHERING_INFO',
  };
}

// ── Facilities ─────────────────────────────────────────────────────────────

async function getFacilities(db) {
  const { results } = await db
    .prepare("SELECT data_blob FROM facilities ORDER BY name")
    .all();
  return results
    .map(r => { try { return JSON.parse(r.data_blob); } catch { return null; } })
    .filter(Boolean);
}

async function upsertFacility(db, f) {
  const m = facilityMeta(f);
  await db.prepare(`
    INSERT INTO facilities (id, name, npi, city, state, masshealth_policy,
      bed_availability, referral_status, disqualified, data_blob, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, npi = excluded.npi, city = excluded.city,
      state = excluded.state,
      masshealth_policy = excluded.masshealth_policy,
      bed_availability = excluded.bed_availability,
      referral_status = excluded.referral_status,
      disqualified = excluded.disqualified,
      data_blob = excluded.data_blob,
      updated_at = datetime('now')
  `).bind(
    m.id, m.name, m.npi, m.city, m.state,
    m.masshealth_policy, m.bed_availability,
    m.referral_status, m.disqualified,
    JSON.stringify(f),
  ).run();
}

// ── Patients ───────────────────────────────────────────────────────────────

async function getPatients(db) {
  const { results } = await db
    .prepare("SELECT data_blob FROM patients ORDER BY name")
    .all();
  return results
    .map(r => { try { return JSON.parse(r.data_blob); } catch { return null; } })
    .filter(Boolean);
}

async function upsertPatient(db, p, recordEvent = false) {
  const m = patientMeta(p);
  if (recordEvent) {
    const old = await db
      .prepare("SELECT placement_stage FROM patients WHERE id = ?")
      .bind(p.id).first();
    if (old && old.placement_stage !== m.placement_stage) {
      await db.prepare(`
        INSERT INTO progress_events (patient_id, event_type, old_value, new_value)
        VALUES (?, 'STAGE_CHANGE', ?, ?)
      `).bind(p.id, old.placement_stage, m.placement_stage).run();
    }
  }
  await db.prepare(`
    INSERT INTO patients (id, name, gender, target_region, placement_stage, data_blob, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, gender = excluded.gender,
      target_region = excluded.target_region,
      placement_stage = excluded.placement_stage,
      data_blob = excluded.data_blob,
      updated_at = datetime('now')
  `).bind(
    m.id, m.name, m.gender, m.target_region, m.placement_stage,
    JSON.stringify(p),
  ).run();
}

// ── Call Logs ──────────────────────────────────────────────────────────────

async function addCallLog(db, facilityId, log) {
  await db.prepare(`
    INSERT INTO call_logs (facility_id, patient_id, timestamp, contact_name, notes, outcome)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    facilityId,
    log.patient_id ?? null,
    log.timestamp ?? new Date().toISOString(),
    log.contact_name ?? null,
    log.notes ?? null,
    log.outcome ?? null,
  ).run();

  if (log.patient_id) {
    await db.prepare(`
      INSERT INTO progress_events (patient_id, facility_id, event_type, new_value)
      VALUES (?, ?, 'CALL_LOGGED', ?)
    `).bind(log.patient_id, facilityId, log.notes ?? '').run();
  }
}

// ── Repatriation ───────────────────────────────────────────────────────────

async function getRepatriation(db) {
  // Stored as a single JSON doc with key = patient_id
  const { results } = await db
    .prepare("SELECT patient_id, stage, status, notes, completed_at FROM repatriation_progress ORDER BY patient_id, stage")
    .all();
  // Reconstruct the flat {stageNum: bool} object the app uses per patient
  const byPatient = {};
  for (const r of results) {
    if (!byPatient[r.patient_id]) byPatient[r.patient_id] = {};
    byPatient[r.patient_id][r.stage] = r.status === 'COMPLETE';
  }
  return byPatient;
}

async function saveRepatriation(db, repatObj) {
  // repatObj is { [patientId]: { [stageNum]: bool } }
  for (const [patientId, stages] of Object.entries(repatObj)) {
    for (const [stage, complete] of Object.entries(stages)) {
      await db.prepare(`
        INSERT INTO repatriation_progress (patient_id, stage, status, completed_at, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(patient_id, stage) DO UPDATE SET
          status = excluded.status,
          completed_at = excluded.completed_at,
          updated_at = datetime('now')
      `).bind(
        patientId,
        parseInt(stage),
        complete ? 'COMPLETE' : 'PENDING',
        complete ? new Date().toISOString() : null,
      ).run();
    }
  }
}

// ── Full pooled state ──────────────────────────────────────────────────────

async function getFullState(db) {
  const [facilities, patients, repatriation] = await Promise.all([
    getFacilities(db),
    getPatients(db),
    getRepatriation(db),
  ]);
  return { facilities, patients, repatriation_progress: repatriation };
}

// ── Router ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const db = env.DB;

    try {
      // GET /api/state — full pooled state
      if (path === '/api/state' && method === 'GET') {
        return json(await getFullState(db));
      }

      // POST /api/state — bulk import all slices
      if (path === '/api/state' && method === 'POST') {
        const body = await request.json();
        const { facilities = [], patients = [], repatriation_progress = {} } = body;
        for (const f of facilities) await upsertFacility(db, f);
        for (const p of patients) await upsertPatient(db, p, false);
        if (Object.keys(repatriation_progress).length) {
          await saveRepatriation(db, repatriation_progress);
        }
        return json({ ok: true });
      }

      // GET /api/facilities
      if (path === '/api/facilities' && method === 'GET') {
        return json(await getFacilities(db));
      }

      // PUT /api/facilities — bulk upsert all facilities
      if (path === '/api/facilities' && method === 'PUT') {
        const facilities = await request.json();
        for (const f of facilities) await upsertFacility(db, f);
        return json({ ok: true });
      }

      // PATCH /api/facilities/:id — update one facility
      const facilityMatch = path.match(/^\/api\/facilities\/(\d+)$/);
      if (facilityMatch) {
        const id = parseInt(facilityMatch[1]);
        if (method === 'PATCH') {
          const body = await request.json();
          await upsertFacility(db, { ...body, id });
          return json({ ok: true });
        }
      }

      // POST /api/facilities/:id/call_logs — add a call log entry
      const callLogMatch = path.match(/^\/api\/facilities\/(\d+)\/call_logs$/);
      if (callLogMatch) {
        const id = parseInt(callLogMatch[1]);
        if (method === 'POST') {
          const body = await request.json();
          await addCallLog(db, id, body);
          return json({ ok: true }, 201);
        }
      }

      // GET /api/patients
      if (path === '/api/patients' && method === 'GET') {
        return json(await getPatients(db));
      }

      // PUT /api/patients — bulk upsert all patients
      if (path === '/api/patients' && method === 'PUT') {
        const patients = await request.json();
        for (const p of patients) await upsertPatient(db, p, true);
        return json({ ok: true });
      }

      // PATCH /api/patients/:id — update one patient (triggers progress event)
      const patientMatch = path.match(/^\/api\/patients\/([^/]+)$/);
      if (patientMatch) {
        const id = patientMatch[1];
        if (method === 'PATCH') {
          const body = await request.json();
          await upsertPatient(db, { ...body, id }, true);
          return json({ ok: true });
        }
      }

      // GET /api/patients/:id/progress — full progress event timeline
      const progressMatch = path.match(/^\/api\/patients\/([^/]+)\/progress$/);
      if (progressMatch) {
        const id = progressMatch[1];
        if (method === 'GET') {
          const { results } = await db
            .prepare("SELECT * FROM progress_events WHERE patient_id = ? ORDER BY created_at DESC")
            .bind(id).all();
          return json(results);
        }
      }

      // GET/PUT /api/repatriation
      if (path === '/api/repatriation') {
        if (method === 'GET') return json(await getRepatriation(db));
        if (method === 'PUT') {
          const body = await request.json();
          await saveRepatriation(db, body);
          return json({ ok: true });
        }
      }

      // GET/POST /api/facilities/:id/email-outreach
      const emailMatch = path.match(/^\/api\/facilities\/(\d+)\/email-outreach$/);
      if (emailMatch) {
        const id = parseInt(emailMatch[1]);
        if (method === 'GET') {
          const { results } = await db
            .prepare('SELECT * FROM email_outreach WHERE facility_id = ? ORDER BY sent_at DESC')
            .bind(id).all();
          return json(results);
        }
        if (method === 'POST') {
          const b = await request.json();
          const { lastRowId } = await db.prepare(`
            INSERT INTO email_outreach
              (facility_id, patient_id, decision_maker_name, decision_maker_role,
               to_email, subject, body, sent_at, follow_up_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id, b.patient_id ?? null,
            b.decision_maker_name ?? null, b.decision_maker_role ?? null,
            b.to_email, b.subject ?? null, b.body ?? null,
            b.sent_at ?? new Date().toISOString(),
            b.follow_up_date ?? null,
          ).run();

          // progress event
          if (b.patient_id) {
            await db.prepare(`
              INSERT INTO progress_events (patient_id, facility_id, event_type, new_value)
              VALUES (?, ?, 'EMAIL_SENT', ?)
            `).bind(b.patient_id, id, b.subject ?? '').run();
          }
          return json({ ok: true, id: lastRowId }, 201);
        }
      }

      // PATCH /api/email-outreach/:id — log outcome
      const outcomePatch = path.match(/^\/api\/email-outreach\/(\d+)\/outcome$/);
      if (outcomePatch && method === 'PATCH') {
        const id = parseInt(outcomePatch[1]);
        const b = await request.json();
        await db.prepare(`
          UPDATE email_outreach
          SET response_received = ?, response_date = ?,
              outcome_status = ?, follow_up_date = ?
          WHERE id = ?
        `).bind(
          b.response_received ? 1 : 0,
          b.response_date ?? null,
          b.outcome_status ?? 'NO_RESPONSE',
          b.follow_up_date ?? null,
          id,
        ).run();

        // progress event
        const row = await db.prepare('SELECT patient_id, facility_id FROM email_outreach WHERE id = ?').bind(id).first();
        if (row?.patient_id) {
          await db.prepare(`
            INSERT INTO progress_events (patient_id, facility_id, event_type, new_value)
            VALUES (?, ?, 'EMAIL_OUTCOME', ?)
          `).bind(row.patient_id, row.facility_id, b.outcome_status ?? 'NO_RESPONSE').run();
        }
        return json({ ok: true });
      }

      return err('Not found', 404);
    } catch (e) {
      console.error(e);
      return err(e.message, 500);
    }
  },
};
