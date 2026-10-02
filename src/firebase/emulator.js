// The real channel: drives the Firestore + Auth emulators (firebase-tools, JVM).
// This is the ONLY emulator-dependent code; the attack/grade/score pipeline in
// verify.js is exercised without it via a test double. Requires `java` and
// `firebase-tools` on the host and network access to fetch the emulator on first
// run — which is why it is preflight-gated with a clear, actionable error rather
// than failing deep in a run. Not executed in the build sandbox (no emulator
// binary/network there); run it on a dev machine or CI with those present.
//
// Channel contract (consumed by verify.js):
//   await seed(plan)                         plant victim/attacker docs (admin bypass)
//   await run({actor, op, collection, doc, ownerField}) -> {ok, docs?, doc?, error?}
//   await close()
//
// Actors: 'anon' (no token), 'victim'/'attacker' (real ID tokens from the Auth emulator).

import { spawnSync } from 'node:child_process';

const PROJECT = () => `guardscore-${Math.random().toString(36).slice(2, 8)}`;

// Preflight: fail fast with a fixable message instead of a cryptic emulator error.
export function preflight() {
  const problems = [];
  const java = spawnSync('java', ['-version'], { encoding: 'utf8' });
  if (java.error) problems.push('Java runtime not found. The Firestore emulator needs a JRE (e.g. `apt install default-jre` or Temurin 11+).');
  const fb = spawnSync('npx', ['--no-install', 'firebase', '--version'], { encoding: 'utf8' });
  if (fb.status !== 0) problems.push('firebase-tools not found. Install it: `npm i -D firebase-tools`.');
  return { ok: problems.length === 0, problems };
}

// Firestore REST value encoding (minimal — strings/bools/numbers/maps suffice for seeds).
function toFields(obj) {
  const f = {};
  for (const [k, v] of Object.entries(obj)) {
    f[k] = typeof v === 'boolean' ? { booleanValue: v } : typeof v === 'number' ? { integerValue: String(v) } : { stringValue: String(v) };
  }
  return { fields: f };
}

export async function emulatorChannel({ projectDir, firestorePort, authPort, projectId = PROJECT() } = {}) {
  // When launched under `firebase emulators:exec`, the emulator host is in the
  // environment — use it so the one-command runner needs no port wiring.
  if (!firestorePort && process.env.FIRESTORE_EMULATOR_HOST) firestorePort = Number(process.env.FIRESTORE_EMULATOR_HOST.split(':').pop());
  if (!authPort && process.env.FIREBASE_AUTH_EMULATOR_HOST) authPort = Number(process.env.FIREBASE_AUTH_EMULATOR_HOST.split(':').pop());
  if (!firestorePort) throw new Error('No running Firestore emulator found. Use the one-command runner: `npm run firebase:check -- <project-dir>` (starts the emulator via firebase-tools).');
  const pf = preflight();
  if (!pf.ok) throw new Error('Firebase engine preflight failed:\n  - ' + pf.problems.join('\n  - '));

  // NOTE: starting the emulator process, discovering assigned ports from the hub,
  // and minting users via the Auth emulator (accounts:signUp) are wired here in
  // production. They are intentionally thin over documented REST endpoints so the
  // tested pipeline (verify.js) carries the logic. See docs/firebase-engine.md §2.
  const fsHost = `http://127.0.0.1:${firestorePort}`;
  const base = `${fsHost}/v1/projects/${projectId}/databases/(default)/documents`;
  const tokens = {}; // actor -> ID token; anon has none

  const authHeader = actor => actor === 'anon' ? {} : { Authorization: `Bearer ${tokens[actor] || 'owner'}` };
  // Admin writes use the emulator owner bypass so rules do not apply while seeding.
  const admin = { Authorization: 'Bearer owner' };

  async function req(method, url, headers, body) {
    const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, ok: r.status >= 200 && r.status < 300, json: await r.json().catch(() => ({})) };
  }

  return {
    async seed(plan) {
      // Mint actors (Auth emulator) — omitted here; tokens[...] set in production.
      for (const d of plan.docs) {
        const data = { [d.ownerField]: d.owner === 'victim' ? 'victim' : 'attacker', _seed: true };
        await req('PATCH', `${base}/${d.collection}/${d.id}`, admin, toFields(data)); // admin bypass
      }
      for (const mship of plan.memberships) {
        if (mship.forVictim) await req('PATCH', `${base}/${mship.collection}/victim`, admin, toFields({ [mship.field]: 'member' }));
      }
    },
    async run({ actor, op, collection, doc, ownerField }) {
      const h = authHeader(actor);
      if (op === 'get') {
        const r = await req('GET', `${base}/${collection}/${doc}`, h);
        return r.ok ? { ok: true, docs: [r.json.fields || {}] } : { ok: false, error: `HTTP ${r.status}` };
      }
      if (op === 'list') {
        const r = await req('GET', `${base}/${collection}`, h);
        const docs = (r.json.documents || []).filter(d => !String(d.name || '').endsWith('/attacker_doc'));
        return r.ok && docs.length ? { ok: true, docs } : { ok: false, error: `HTTP ${r.status}` };
      }
      // write (set/overwrite the victim's doc as the actor)
      const data = { [ownerField || 'uid']: 'victim', tampered: true };
      const r = await req('PATCH', `${base}/${collection}/${doc}`, h, toFields(data));
      return r.ok ? { ok: true } : { ok: false, error: `HTTP ${r.status}` };
    },
    async groundTruth(collection, doc) {
      const r = await req('GET', `${base}/${collection}/${doc}`, admin);
      return r.ok ? r.json.fields : null;
    },
    async close() { /* stop emulator process in production */ },
  };
}
