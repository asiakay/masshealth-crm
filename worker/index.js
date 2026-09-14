import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Tiny base64url helpers (Workers have btoa/atob) ────────────────────────

function uint8ToBase64url(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToUint8(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - padded.length % 4) % 4;
  const binary = atob(padded + '='.repeat(pad));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return uint8ToBase64url(bytes);
}

function rpIDFromOrigin(origin) {
  try { return new URL(origin).hostname; } catch { return 'localhost'; }
}

// ── Auth check ─────────────────────────────────────────────────────────────

async function isAuthenticated(request, env) {
  if (request.headers.get('Cf-Access-Authenticated-User-Email')) return true;

  const header = request.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) return false;

  // Legacy WRITE_TOKEN (still supported for local dev)
  if (env.WRITE_TOKEN && token === env.WRITE_TOKEN) return true;

  // Session token check
  try {
    const row = await env.DB.prepare(
      "SELECT id FROM sessions WHERE id = ? AND expires_at > datetime('now')"
    ).bind(token).first();
    return !!row;
  } catch {
    return false;
  }
}

// ── JSON helpers ───────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── Auth routes ────────────────────────────────────────────────────────────

async function handleAuth(path, request, env) {
  const method = request.method;

  // GET /api/auth/setup-status — has a passkey been registered?
  if (path === '/api/auth/setup-status' && method === 'GET') {
    try {
      const row = await env.DB.prepare('SELECT COUNT(*) as n FROM webauthn_credentials').first();
      return json({ hasCredentials: (row?.n ?? 0) > 0 });
    } catch {
      return json({ hasCredentials: false });
    }
  }

  // GET /api/auth/me — is the current session valid?
  if (path === '/api/auth/me' && method === 'GET') {
    const auth = await isAuthenticated(request, env);
    return json({ authenticated: auth });
  }

  // GET /api/auth/registration-options
  if (path === '/api/auth/registration-options' && method === 'GET') {
    const origin = request.headers.get('Origin') ?? '';
    const rpID = env.RP_ID ?? rpIDFromOrigin(origin);

    const options = await generateRegistrationOptions({
      rpName: 'MassHealth CRM',
      rpID,
      userName: 'asia',
      userID: new TextEncoder().encode('asia'),
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    // Clean up stale challenges, then store new one
    await env.DB.prepare(
      "DELETE FROM challenges WHERE created_at < datetime('now', '-10 minutes')"
    ).run().catch(() => {});
    await env.DB.prepare(
      "INSERT OR IGNORE INTO challenges (id, type, origin) VALUES (?, 'registration', ?)"
    ).bind(options.challenge, origin).run();

    return json(options);
  }

  // POST /api/auth/register
  if (path === '/api/auth/register' && method === 'POST') {
    const body = await request.json();

    const challenge = await env.DB.prepare(
      "SELECT id, origin FROM challenges WHERE type = 'registration' ORDER BY created_at DESC LIMIT 1"
    ).first();
    if (!challenge) return err('No pending registration challenge — try again', 400);
    await env.DB.prepare('DELETE FROM challenges WHERE id = ?').bind(challenge.id).run();

    const rpID = env.RP_ID ?? rpIDFromOrigin(challenge.origin ?? '');
    const rpOrigin = env.RP_ORIGIN ?? challenge.origin ?? `https://${rpID}`;

    let result;
    try {
      result = await verifyRegistrationResponse({
        response: body,
        expectedChallenge: challenge.id,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
      });
    } catch (e) {
      return err(`Verification failed: ${e.message}`, 400);
    }

    if (!result.verified || !result.registrationInfo) {
      return err('Registration could not be verified', 400);
    }

    const { credential } = result.registrationInfo;

    await env.DB.prepare(`
      INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, transports)
      VALUES (?, 'asia', ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        public_key = excluded.public_key,
        sign_count = excluded.sign_count,
        transports = excluded.transports
    `).bind(
      credential.id,
      uint8ToBase64url(credential.publicKey),
      credential.counter,
      JSON.stringify(credential.transports ?? []),
    ).run();

    const sessionId = await randomToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      .toISOString().replace('T', ' ').slice(0, 19);
    await env.DB.prepare(
      "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, 'asia', ?)"
    ).bind(sessionId, expiresAt).run();

    return json({ verified: true, sessionToken: sessionId });
  }

  // GET /api/auth/authentication-options
  if (path === '/api/auth/authentication-options' && method === 'GET') {
    const origin = request.headers.get('Origin') ?? '';
    const rpID = env.RP_ID ?? rpIDFromOrigin(origin);

    const { results } = await env.DB.prepare('SELECT id FROM webauthn_credentials').all();

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: results.map(c => ({ id: c.id, type: 'public-key' })),
      userVerification: 'preferred',
    });

    await env.DB.prepare(
      "DELETE FROM challenges WHERE created_at < datetime('now', '-10 minutes')"
    ).run().catch(() => {});
    await env.DB.prepare(
      "INSERT OR IGNORE INTO challenges (id, type, origin) VALUES (?, 'authentication', ?)"
    ).bind(options.challenge, origin).run();

    return json(options);
  }

  // POST /api/auth/login
  if (path === '/api/auth/login' && method === 'POST') {
    const body = await request.json();

    const challenge = await env.DB.prepare(
      "SELECT id, origin FROM challenges WHERE type = 'authentication' ORDER BY created_at DESC LIMIT 1"
    ).first();
    if (!challenge) return err('No pending authentication challenge — try again', 400);
    await env.DB.prepare('DELETE FROM challenges WHERE id = ?').bind(challenge.id).run();

    const rpID = env.RP_ID ?? rpIDFromOrigin(challenge.origin ?? '');
    const rpOrigin = env.RP_ORIGIN ?? challenge.origin ?? `https://${rpID}`;

    const cred = await env.DB.prepare(
      'SELECT * FROM webauthn_credentials WHERE id = ?'
    ).bind(body.id).first();
    if (!cred) return err('Unknown credential', 400);

    let result;
    try {
      result = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge: challenge.id,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
        credential: {
          id: cred.id,
          publicKey: base64urlToUint8(cred.public_key),
          counter: cred.sign_count,
        },
      });
    } catch (e) {
      return err(`Authentication failed: ${e.message}`, 401);
    }

    if (!result.verified) return err('Authentication not verified', 401);

    await env.DB.prepare(
      'UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?'
    ).bind(result.authenticationInfo.newCounter, cred.id).run();

    const sessionId = await randomToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      .toISOString().replace('T', ' ').slice(0, 19);
    await env.DB.prepare(
      "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, 'asia', ?)"
    ).bind(sessionId, expiresAt).run();

    return json({ verified: true, sessionToken: sessionId });
  }

  // POST /api/auth/logout
  if (path === '/api/auth/logout' && method === 'POST') {
    const header = request.headers.get('Authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    if (token) {
      await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run().catch(() => {});
    }
    return json({ ok: true });
  }

  return err('Not found', 404);
}

// ── Facilities ─────────────────────────────────────────────────────────────

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

async function getFacilities(db) {
  const { results } = await db
    .prepare('SELECT data_blob FROM facilities ORDER BY name')
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

function patientMeta(p) {
  return {
    id: p.id,
    name: p.name ?? '',
    gender: p.gender ?? null,
    target_region: p.target_region ?? null,
    placement_stage: p.placement_stage ?? 'GATHERING_INFO',
  };
}

async function getPatients(db) {
  const { results } = await db
    .prepare('SELECT data_blob FROM patients ORDER BY name')
    .all();
  return results
    .map(r => { try { return JSON.parse(r.data_blob); } catch { return null; } })
    .filter(Boolean);
}

async function upsertPatient(db, p, recordEvent = false) {
  const m = patientMeta(p);
  if (recordEvent) {
    const old = await db
      .prepare('SELECT placement_stage FROM patients WHERE id = ?')
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
  const { results } = await db
    .prepare('SELECT patient_id, stage, status FROM repatriation_progress ORDER BY patient_id, stage')
    .all();
  const byPatient = {};
  for (const r of results) {
    if (!byPatient[r.patient_id]) byPatient[r.patient_id] = {};
    byPatient[r.patient_id][r.stage] = r.status === 'COMPLETE';
  }
  return byPatient;
}

async function saveRepatriation(db, repatObj) {
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

async function getFullState(db) {
  const [facilities, patients, repatriation] = await Promise.all([
    getFacilities(db),
    getPatients(db),
    getRepatriation(db),
  ]);
  return { facilities, patients, repatriation_progress: repatriation };
}

// ── Main router ────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Auth routes always use env.DB (real DB)
    if (path.startsWith('/api/auth/')) {
      return handleAuth(path, request, env);
    }

    const authenticated = await isAuthenticated(request, env);
    const db = authenticated ? env.DB : env.DEMO_DB;

    if (!authenticated && method !== 'GET' && method !== 'HEAD') {
      return json(
        { error: 'Demo mode: authenticate to perform write operations' },
        403,
      );
    }

    try {
      if (path === '/api/state' && method === 'GET') {
        return json(await getFullState(db));
      }

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

      if (path === '/api/facilities' && method === 'GET') {
        return json(await getFacilities(db));
      }

      if (path === '/api/facilities' && method === 'PUT') {
        const facilities = await request.json();
        for (const f of facilities) await upsertFacility(db, f);
        return json({ ok: true });
      }

      const facilityMatch = path.match(/^\/api\/facilities\/(\d+)$/);
      if (facilityMatch) {
        const id = parseInt(facilityMatch[1]);
        if (method === 'PATCH') {
          const body = await request.json();
          await upsertFacility(db, { ...body, id });
          return json({ ok: true });
        }
      }

      const callLogMatch = path.match(/^\/api\/facilities\/(\d+)\/call_logs$/);
      if (callLogMatch) {
        const id = parseInt(callLogMatch[1]);
        if (method === 'POST') {
          const body = await request.json();
          await addCallLog(db, id, body);
          return json({ ok: true }, 201);
        }
      }

      if (path === '/api/patients' && method === 'GET') {
        return json(await getPatients(db));
      }

      if (path === '/api/patients' && method === 'PUT') {
        const patients = await request.json();
        for (const p of patients) await upsertPatient(db, p, true);
        return json({ ok: true });
      }

      const patientMatch = path.match(/^\/api\/patients\/([^/]+)$/);
      if (patientMatch) {
        const id = patientMatch[1];
        if (method === 'PATCH') {
          const body = await request.json();
          await upsertPatient(db, { ...body, id }, true);
          return json({ ok: true });
        }
      }

      const progressMatch = path.match(/^\/api\/patients\/([^/]+)\/progress$/);
      if (progressMatch) {
        const id = progressMatch[1];
        if (method === 'GET') {
          const { results } = await db
            .prepare('SELECT * FROM progress_events WHERE patient_id = ? ORDER BY created_at DESC')
            .bind(id).all();
          return json(results);
        }
      }

      if (path === '/api/repatriation') {
        if (method === 'GET') return json(await getRepatriation(db));
        if (method === 'PUT') {
          const body = await request.json();
          await saveRepatriation(db, body);
          return json({ ok: true });
        }
      }

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

          if (b.patient_id) {
            await db.prepare(`
              INSERT INTO progress_events (patient_id, facility_id, event_type, new_value)
              VALUES (?, ?, 'EMAIL_SENT', ?)
            `).bind(b.patient_id, id, b.subject ?? '').run();
          }
          return json({ ok: true, id: lastRowId }, 201);
        }
      }

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

        const row = await db
          .prepare('SELECT patient_id, facility_id FROM email_outreach WHERE id = ?')
          .bind(id).first();
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
