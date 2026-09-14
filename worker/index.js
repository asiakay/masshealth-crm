// No external dependencies — WebAuthn verification uses the Workers Web Crypto API.
// Auth routes: setup-status · registration-options · register
//              authentication-options · login · logout · me
// Data routes: /api/state · /api/facilities · /api/patients · /api/repatriation

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Base64url helpers ──────────────────────────────────────────────────────

function uint8ToBase64url(bytes) {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToUint8(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - s.length % 4) % 4;
  const bin = atob(s + '='.repeat(pad));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function randomToken() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return uint8ToBase64url(b);
}

function rpIDFromOrigin(origin) {
  try { return new URL(origin).hostname; } catch { return 'localhost'; }
}

// ── Minimal CBOR decoder (maps, bytes, text, integers — enough for attestationObject) ──

function cborDecode(input) {
  const u = input instanceof Uint8Array ? input : new Uint8Array(input);
  const dv = new DataView(u.buffer, u.byteOffset, u.byteLength);
  let pos = 0;

  function read() {
    const byte = u[pos++];
    const mt = byte >> 5;
    const ai = byte & 0x1f;
    let val;

    if (ai < 24) val = ai;
    else if (ai === 24) val = u[pos++];
    else if (ai === 25) { val = dv.getUint16(pos, false); pos += 2; }
    else if (ai === 26) { val = dv.getUint32(pos, false); pos += 4; }
    else val = 0;

    switch (mt) {
      case 0: return val;
      case 1: return -(val + 1);
      case 2: { const b = u.slice(pos, pos + val); pos += val; return b; }
      case 3: { const b = u.slice(pos, pos + val); pos += val; return new TextDecoder().decode(b); }
      case 4: { const a = []; for (let i = 0; i < val; i++) a.push(read()); return a; }
      case 5: {
        const m = new Map();
        for (let i = 0; i < val; i++) { const k = read(); m.set(k, read()); }
        return m;
      }
      case 7:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        return undefined;
      default: throw new Error(`CBOR: unsupported major type ${mt}`);
    }
  }

  return read();
}

// ── authenticatorData parser ───────────────────────────────────────────────

function parseAuthData(authData) {
  let off = 0;
  const rpIdHash = authData.slice(off, off + 32); off += 32;
  const flags = authData[off++];
  const signCount = new DataView(authData.buffer, authData.byteOffset + off, 4).getUint32(0, false);
  off += 4;

  let credentialId = null;
  let coseKey = null;

  if (flags & 0x40) { // AT flag — attested credential data present
    off += 16; // skip aaguid
    const idLen = (authData[off] << 8) | authData[off + 1]; off += 2;
    credentialId = authData.slice(off, off + idLen); off += idLen;
    coseKey = cborDecode(authData.slice(off));
  }

  return { rpIdHash, flags, signCount, credentialId, coseKey };
}

// ── COSE public key → Web Crypto CryptoKey ─────────────────────────────────

async function importCOSEKey(coseKey) {
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);

  if (kty === 2 && alg === -7) { // EC2, ES256 (P-256)
    const x = coseKey.get(-2);
    const y = coseKey.get(-3);
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(x, 1);
    raw.set(y, 33);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', raw,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify'],
    );
    const spki = await crypto.subtle.exportKey('spki', cryptoKey);
    return { alg: 'ES256', spki: uint8ToBase64url(new Uint8Array(spki)) };
  }

  if (kty === 3 && (alg === -257 || alg === undefined)) { // RSA, RS256
    const n = coseKey.get(-1);
    const e_bytes = coseKey.get(-2);
    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', alg: 'RS256', n: uint8ToBase64url(n), e: uint8ToBase64url(e_bytes), ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true, ['verify'],
    );
    const spki = await crypto.subtle.exportKey('spki', cryptoKey);
    return { alg: 'RS256', spki: uint8ToBase64url(new Uint8Array(spki)) };
  }

  throw new Error(`Unsupported COSE key: kty=${kty} alg=${alg}`);
}

async function importSPKIKey(alg, spkiB64url) {
  const spki = base64urlToUint8(spkiB64url);
  if (alg === 'ES256') {
    return crypto.subtle.importKey(
      'spki', spki,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['verify'],
    );
  }
  if (alg === 'RS256') {
    return crypto.subtle.importKey(
      'spki', spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false, ['verify'],
    );
  }
  throw new Error(`Unsupported alg: ${alg}`);
}

// ── DER ECDSA signature → raw (r || s) ────────────────────────────────────

function derToRaw(derSig) {
  let off = 0;
  if (derSig[off++] !== 0x30) throw new Error('DER: expected SEQUENCE');
  const seqLen = derSig[off] & 0x80 ? (() => { const n = derSig[off++] & 0x7f; let l = 0; for (let i = 0; i < n; i++) l = (l << 8) | derSig[off++]; return l; })() : derSig[off++];
  if (derSig[off++] !== 0x02) throw new Error('DER: expected INTEGER (r)');
  const rLen = derSig[off++];
  let r = derSig.slice(off, off + rLen); off += rLen;
  if (derSig[off++] !== 0x02) throw new Error('DER: expected INTEGER (s)');
  const sLen = derSig[off++];
  let s = derSig.slice(off, off + sLen);

  function to32(b) {
    if (b.length === 33 && b[0] === 0) b = b.slice(1);
    if (b.length < 32) { const p = new Uint8Array(32); p.set(b, 32 - b.length); return p; }
    return b.slice(0, 32);
  }

  const out = new Uint8Array(64);
  out.set(to32(r), 0);
  out.set(to32(s), 32);
  return out;
}

// ── WebAuthn registration verification ────────────────────────────────────

async function verifyRegistration({ response, expectedChallenge, expectedOrigin, expectedRPID }) {
  const clientDataBytes = base64urlToUint8(response.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.create') throw new Error('Wrong clientData type');
  if (clientData.challenge !== expectedChallenge) throw new Error('Challenge mismatch');
  if (clientData.origin !== expectedOrigin) throw new Error(`Origin mismatch: got ${clientData.origin}, expected ${expectedOrigin}`);

  const attObj = cborDecode(base64urlToUint8(response.response.attestationObject));
  const authDataBytes = attObj.get('authData') ?? attObj['authData'];
  const parsed = parseAuthData(authDataBytes);

  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRPID)));
  for (let i = 0; i < 32; i++) {
    if (parsed.rpIdHash[i] !== expectedRpIdHash[i]) throw new Error('RP ID hash mismatch');
  }
  if (!(parsed.flags & 0x01)) throw new Error('User not present');

  const keyInfo = await importCOSEKey(parsed.coseKey);

  return {
    verified: true,
    credential: {
      id: uint8ToBase64url(parsed.credentialId),
      alg: keyInfo.alg,
      publicKeySPKI: keyInfo.spki,
      counter: parsed.signCount,
      transports: response.response.transports ?? [],
    },
  };
}

// ── WebAuthn authentication verification ──────────────────────────────────

async function verifyAuthentication({ response, expectedChallenge, expectedOrigin, expectedRPID, credential }) {
  const clientDataBytes = base64urlToUint8(response.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

  if (clientData.type !== 'webauthn.get') throw new Error('Wrong clientData type');
  if (clientData.challenge !== expectedChallenge) throw new Error('Challenge mismatch');
  if (clientData.origin !== expectedOrigin) throw new Error(`Origin mismatch: got ${clientData.origin}, expected ${expectedOrigin}`);

  const authDataBytes = base64urlToUint8(response.response.authenticatorData);
  const parsed = parseAuthData(authDataBytes);

  const expectedRpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRPID)));
  for (let i = 0; i < 32; i++) {
    if (parsed.rpIdHash[i] !== expectedRpIdHash[i]) throw new Error('RP ID hash mismatch');
  }
  if (!(parsed.flags & 0x01)) throw new Error('User not present');

  const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataBytes);
  const signedData = new Uint8Array(authDataBytes.length + 32);
  signedData.set(authDataBytes, 0);
  signedData.set(new Uint8Array(clientDataHash), authDataBytes.length);

  const sigBytes = base64urlToUint8(response.response.signature);
  const cryptoKey = await importSPKIKey(credential.alg, credential.publicKeySPKI);

  let verified;
  if (credential.alg === 'ES256') {
    verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      derToRaw(sigBytes),
      signedData,
    );
  } else {
    verified = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      cryptoKey,
      sigBytes,
      signedData,
    );
  }

  return { verified, newCounter: parsed.signCount };
}

// ── generateOptions helpers ────────────────────────────────────────────────

async function generateChallenge() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return uint8ToBase64url(b);
}

// ── Auth check ─────────────────────────────────────────────────────────────

async function isAuthenticated(request, env) {
  if (request.headers.get('Cf-Access-Authenticated-User-Email')) return true;

  const header = request.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token) return false;

  if (env.WRITE_TOKEN && token === env.WRITE_TOKEN) return true;

  try {
    const row = await env.DB.prepare(
      "SELECT id FROM sessions WHERE id = ? AND expires_at > datetime('now')"
    ).bind(token).first();
    return !!row;
  } catch { return false; }
}

// ── JSON helpers ───────────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) { return json({ error: msg }, status); }

// ── Auth routes ────────────────────────────────────────────────────────────

async function handleAuth(path, request, env) {
  const method = request.method;

  if (path === '/api/auth/setup-status' && method === 'GET') {
    try {
      const row = await env.DB.prepare('SELECT COUNT(*) as n FROM webauthn_credentials').first();
      return json({ hasCredentials: (row?.n ?? 0) > 0 });
    } catch { return json({ hasCredentials: false }); }
  }

  if (path === '/api/auth/me' && method === 'GET') {
    return json({ authenticated: await isAuthenticated(request, env) });
  }

  if (path === '/api/auth/registration-options' && method === 'GET') {
    const origin = request.headers.get('Origin') ?? '';
    const rpID = env.RP_ID ?? rpIDFromOrigin(origin);
    const challenge = await generateChallenge();

    await env.DB.prepare("DELETE FROM challenges WHERE created_at < datetime('now', '-10 minutes')").run().catch(() => {});
    await env.DB.prepare("INSERT OR IGNORE INTO challenges (id, type, origin) VALUES (?, 'registration', ?)").bind(challenge, origin).run();

    // Return PublicKeyCredentialCreationOptions-compatible JSON
    return json({
      challenge,
      rp: { name: 'MassHealth CRM', id: rpID },
      user: {
        id: uint8ToBase64url(new TextEncoder().encode('asia')),
        name: 'asia',
        displayName: 'Asia',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      attestation: 'none',
      timeout: 60000,
    });
  }

  if (path === '/api/auth/register' && method === 'POST') {
    // If any credential already exists, require an authenticated session so
    // a random caller cannot take over the account after initial setup.
    const countRow = await env.DB.prepare('SELECT COUNT(*) as n FROM webauthn_credentials').first().catch(() => null);
    if ((countRow?.n ?? 0) > 0 && !(await isAuthenticated(request, env))) {
      return err('Already registered — authenticate to add another passkey', 403);
    }

    const body = await request.json();

    // Resolve the challenge from the submitted clientDataJSON rather than
    // blindly picking the newest row, so concurrent sessions don't consume
    // each other's challenges.
    let submittedChallenge;
    try {
      const cd = JSON.parse(new TextDecoder().decode(base64urlToUint8(body.response?.clientDataJSON ?? '')));
      submittedChallenge = cd.challenge;
    } catch (e) { return err('Invalid clientDataJSON', 400); }

    const challenge = await env.DB.prepare(
      "SELECT id, origin FROM challenges WHERE id = ? AND type = 'registration'"
    ).bind(submittedChallenge).first();
    if (!challenge) return err('No pending registration challenge — try again', 400);
    await env.DB.prepare('DELETE FROM challenges WHERE id = ?').bind(challenge.id).run();

    const rpID = env.RP_ID ?? rpIDFromOrigin(challenge.origin ?? '');
    const rpOrigin = env.RP_ORIGIN ?? challenge.origin ?? `https://${rpID}`;

    let result;
    try {
      result = await verifyRegistration({
        response: body,
        expectedChallenge: challenge.id,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
      });
    } catch (e) { return err(`Registration failed: ${e.message}`, 400); }

    if (!result.verified) return err('Registration not verified', 400);

    const { id, alg, publicKeySPKI, counter, transports } = result.credential;
    await env.DB.prepare(`
      INSERT INTO webauthn_credentials (id, user_id, alg, public_key, sign_count, transports)
      VALUES (?, 'asia', ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        alg = excluded.alg, public_key = excluded.public_key,
        sign_count = excluded.sign_count, transports = excluded.transports
    `).bind(id, alg, publicKeySPKI, counter, JSON.stringify(transports)).run();

    const sessionId = await randomToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, 'asia', ?)").bind(sessionId, expiresAt).run();

    return json({ verified: true, sessionToken: sessionId });
  }

  if (path === '/api/auth/authentication-options' && method === 'GET') {
    const origin = request.headers.get('Origin') ?? '';
    const rpID = env.RP_ID ?? rpIDFromOrigin(origin);
    const challenge = await generateChallenge();

    const { results } = await env.DB.prepare('SELECT id FROM webauthn_credentials').all();

    await env.DB.prepare("DELETE FROM challenges WHERE created_at < datetime('now', '-10 minutes')").run().catch(() => {});
    await env.DB.prepare("INSERT OR IGNORE INTO challenges (id, type, origin) VALUES (?, 'authentication', ?)").bind(challenge, origin).run();

    return json({
      challenge,
      rpId: rpID,
      allowCredentials: results.map(c => ({ type: 'public-key', id: c.id })),
      userVerification: 'preferred',
      timeout: 60000,
    });
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const body = await request.json();

    // Look up the exact challenge the client submitted, not the newest row.
    let submittedChallenge;
    try {
      const cd = JSON.parse(new TextDecoder().decode(base64urlToUint8(body.response?.clientDataJSON ?? '')));
      submittedChallenge = cd.challenge;
    } catch (e) { return err('Invalid clientDataJSON', 400); }

    const challenge = await env.DB.prepare(
      "SELECT id, origin FROM challenges WHERE id = ? AND type = 'authentication'"
    ).bind(submittedChallenge).first();
    if (!challenge) return err('No pending authentication challenge — try again', 400);
    await env.DB.prepare('DELETE FROM challenges WHERE id = ?').bind(challenge.id).run();

    const cred = await env.DB.prepare('SELECT * FROM webauthn_credentials WHERE id = ?').bind(body.id).first();
    if (!cred) return err('Unknown credential', 400);

    const rpID = env.RP_ID ?? rpIDFromOrigin(challenge.origin ?? '');
    const rpOrigin = env.RP_ORIGIN ?? challenge.origin ?? `https://${rpID}`;

    let result;
    try {
      result = await verifyAuthentication({
        response: body,
        expectedChallenge: challenge.id,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
        credential: { alg: cred.alg, publicKeySPKI: cred.public_key },
      });
    } catch (e) { return err(`Authentication failed: ${e.message}`, 401); }

    if (!result.verified) return err('Authentication not verified', 401);

    // Reject a repeated or decreasing counter — sign of a cloned credential.
    // Exception: authenticators that always report 0 are allowed.
    if (result.newCounter !== 0 && result.newCounter <= cred.sign_count) {
      return err('Authenticator counter did not increase — possible credential clone', 401);
    }

    await env.DB.prepare('UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?').bind(result.newCounter, cred.id).run();

    const sessionId = await randomToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19);
    await env.DB.prepare("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, 'asia', ?)").bind(sessionId, expiresAt).run();

    return json({ verified: true, sessionToken: sessionId });
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const header = request.headers.get('Authorization') ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run().catch(() => {});
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
  const { results } = await db.prepare('SELECT data_blob FROM facilities ORDER BY name').all();
  return results.map(r => { try { return JSON.parse(r.data_blob); } catch { return null; } }).filter(Boolean);
}

async function upsertFacility(db, f) {
  const m = facilityMeta(f);
  await db.prepare(`
    INSERT INTO facilities (id, name, npi, city, state, masshealth_policy,
      bed_availability, referral_status, disqualified, data_blob, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, npi = excluded.npi, city = excluded.city,
      state = excluded.state, masshealth_policy = excluded.masshealth_policy,
      bed_availability = excluded.bed_availability,
      referral_status = excluded.referral_status,
      disqualified = excluded.disqualified,
      data_blob = excluded.data_blob, updated_at = datetime('now')
  `).bind(m.id, m.name, m.npi, m.city, m.state, m.masshealth_policy,
    m.bed_availability, m.referral_status, m.disqualified, JSON.stringify(f)).run();
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
  const { results } = await db.prepare('SELECT data_blob FROM patients ORDER BY name').all();
  return results.map(r => { try { return JSON.parse(r.data_blob); } catch { return null; } }).filter(Boolean);
}

async function upsertPatient(db, p, recordEvent = false) {
  const m = patientMeta(p);
  if (recordEvent) {
    const old = await db.prepare('SELECT placement_stage FROM patients WHERE id = ?').bind(p.id).first();
    if (old && old.placement_stage !== m.placement_stage) {
      await db.prepare(
        "INSERT INTO progress_events (patient_id, event_type, old_value, new_value) VALUES (?, 'STAGE_CHANGE', ?, ?)"
      ).bind(p.id, old.placement_stage, m.placement_stage).run();
    }
  }
  await db.prepare(`
    INSERT INTO patients (id, name, gender, target_region, placement_stage, data_blob, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, gender = excluded.gender,
      target_region = excluded.target_region,
      placement_stage = excluded.placement_stage,
      data_blob = excluded.data_blob, updated_at = datetime('now')
  `).bind(m.id, m.name, m.gender, m.target_region, m.placement_stage, JSON.stringify(p)).run();
}

// ── Call Logs ──────────────────────────────────────────────────────────────

async function addCallLog(db, facilityId, log) {
  await db.prepare(
    'INSERT INTO call_logs (facility_id, patient_id, timestamp, contact_name, notes, outcome) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(facilityId, log.patient_id ?? null, log.timestamp ?? new Date().toISOString(),
    log.contact_name ?? null, log.notes ?? null, log.outcome ?? null).run();
  if (log.patient_id) {
    await db.prepare(
      "INSERT INTO progress_events (patient_id, facility_id, event_type, new_value) VALUES (?, ?, 'CALL_LOGGED', ?)"
    ).bind(log.patient_id, facilityId, log.notes ?? '').run();
  }
}

// ── Repatriation ───────────────────────────────────────────────────────────

async function getRepatriation(db) {
  const { results } = await db.prepare(
    'SELECT patient_id, stage, status FROM repatriation_progress ORDER BY patient_id, stage'
  ).all();
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
          status = excluded.status, completed_at = excluded.completed_at, updated_at = datetime('now')
      `).bind(patientId, parseInt(stage), complete ? 'COMPLETE' : 'PENDING', complete ? new Date().toISOString() : null).run();
    }
  }
}

async function getFullState(db) {
  const [facilities, patients, repatriation] = await Promise.all([
    getFacilities(db), getPatients(db), getRepatriation(db),
  ]);
  return { facilities, patients, repatriation_progress: repatriation };
}

// ── Migration: add alg column if missing (backwards-compat) ───────────────

async function ensureAlgColumn(db) {
  try {
    await db.prepare("SELECT alg FROM webauthn_credentials LIMIT 1").first();
  } catch {
    await db.prepare("ALTER TABLE webauthn_credentials ADD COLUMN alg TEXT NOT NULL DEFAULT 'ES256'").run().catch(() => {});
  }
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

    if (path.startsWith('/api/auth/')) return handleAuth(path, request, env);

    const authenticated = await isAuthenticated(request, env);
    const db = authenticated ? env.DB : env.DEMO_DB;

    if (!authenticated && method !== 'GET' && method !== 'HEAD') {
      return json({ error: 'Demo mode: authenticate to perform write operations' }, 403);
    }

    try {
      if (path === '/api/state' && method === 'GET') return json(await getFullState(db));

      if (path === '/api/state' && method === 'POST') {
        const { facilities = [], patients = [], repatriation_progress = {} } = await request.json();
        for (const f of facilities) await upsertFacility(db, f);
        for (const p of patients) await upsertPatient(db, p, false);
        if (Object.keys(repatriation_progress).length) await saveRepatriation(db, repatriation_progress);
        return json({ ok: true });
      }

      if (path === '/api/facilities' && method === 'GET') return json(await getFacilities(db));

      if (path === '/api/facilities' && method === 'PUT') {
        for (const f of await request.json()) await upsertFacility(db, f);
        return json({ ok: true });
      }

      const facilityMatch = path.match(/^\/api\/facilities\/(\d+)$/);
      if (facilityMatch && method === 'PATCH') {
        const body = await request.json();
        await upsertFacility(db, { ...body, id: parseInt(facilityMatch[1]) });
        return json({ ok: true });
      }

      const callLogMatch = path.match(/^\/api\/facilities\/(\d+)\/call_logs$/);
      if (callLogMatch && method === 'POST') {
        await addCallLog(db, parseInt(callLogMatch[1]), await request.json());
        return json({ ok: true }, 201);
      }

      if (path === '/api/patients' && method === 'GET') return json(await getPatients(db));

      if (path === '/api/patients' && method === 'PUT') {
        for (const p of await request.json()) await upsertPatient(db, p, true);
        return json({ ok: true });
      }

      const patientMatch = path.match(/^\/api\/patients\/([^/]+)$/);
      if (patientMatch && method === 'PATCH') {
        const body = await request.json();
        await upsertPatient(db, { ...body, id: patientMatch[1] }, true);
        return json({ ok: true });
      }

      const progressMatch = path.match(/^\/api\/patients\/([^/]+)\/progress$/);
      if (progressMatch && method === 'GET') {
        const { results } = await db.prepare(
          'SELECT * FROM progress_events WHERE patient_id = ? ORDER BY created_at DESC'
        ).bind(progressMatch[1]).all();
        return json(results);
      }

      if (path === '/api/repatriation') {
        if (method === 'GET') return json(await getRepatriation(db));
        if (method === 'PUT') { await saveRepatriation(db, await request.json()); return json({ ok: true }); }
      }

      const emailMatch = path.match(/^\/api\/facilities\/(\d+)\/email-outreach$/);
      if (emailMatch) {
        const id = parseInt(emailMatch[1]);
        if (method === 'GET') {
          const { results } = await db.prepare(
            'SELECT * FROM email_outreach WHERE facility_id = ? ORDER BY sent_at DESC'
          ).bind(id).all();
          return json(results);
        }
        if (method === 'POST') {
          const b = await request.json();
          const { lastRowId } = await db.prepare(`
            INSERT INTO email_outreach
              (facility_id, patient_id, decision_maker_name, decision_maker_role,
               to_email, subject, body, sent_at, follow_up_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(id, b.patient_id ?? null, b.decision_maker_name ?? null, b.decision_maker_role ?? null,
            b.to_email, b.subject ?? null, b.body ?? null,
            b.sent_at ?? new Date().toISOString(), b.follow_up_date ?? null).run();
          if (b.patient_id) {
            await db.prepare(
              "INSERT INTO progress_events (patient_id, facility_id, event_type, new_value) VALUES (?, ?, 'EMAIL_SENT', ?)"
            ).bind(b.patient_id, id, b.subject ?? '').run();
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
          SET response_received = ?, response_date = ?, outcome_status = ?, follow_up_date = ?
          WHERE id = ?
        `).bind(b.response_received ? 1 : 0, b.response_date ?? null,
          b.outcome_status ?? 'NO_RESPONSE', b.follow_up_date ?? null, id).run();
        const row = await db.prepare('SELECT patient_id, facility_id FROM email_outreach WHERE id = ?').bind(id).first();
        if (row?.patient_id) {
          await db.prepare(
            "INSERT INTO progress_events (patient_id, facility_id, event_type, new_value) VALUES (?, ?, 'EMAIL_OUTCOME', ?)"
          ).bind(row.patient_id, row.facility_id, b.outcome_status ?? 'NO_RESPONSE').run();
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
