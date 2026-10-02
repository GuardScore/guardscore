// Firebase attack engine — the gauntlet, grading, scoring, and proof. Mirrors
// the Supabase engine's contract (src/verify.js): same verdicts, same Guard
// Score caps, every finding carries a proof receipt {actor, op, observed}.
//
// The `channel` is injected so this whole pipeline is unit-testable WITHOUT a
// live emulator (see test/firebase-engine.js). In production the channel is the
// real Firestore-emulator driver from ./emulator.js; the emulator — not this
// file — decides allow/deny, so we never re-implement the rules VM.

import { parseRules, seedPlan, attackSpecs, legitSpecs, storageSpecs, collectionOf } from './rules.js';

const EXPLAIN = {
  anon_read: 'An anonymous visitor read another user’s document here.',
  cross_user_read: 'A signed-in user read another user’s document here.',
  list_leak: 'A query returned documents the caller does not own — the collection leaks under list even if single-doc reads look scoped.',
  anon_write: 'An anonymous visitor created or overwrote a document here.',
  cross_user_write: 'A signed-in user overwrote another user’s document here.',
  collection_group_bypass: 'A collectionGroup query returned other users’ documents — the per-collection rule never covered the group query.',
  field_tamper: 'The document owner set a privileged field (role/plan/credits) on their own document — the rule does not pin it, so a user can self-escalate.',
  authority_bypass: 'An attacker wrote their own document into the collection a role gate trusts, then passed the gate — the authority table is attacker-writable.',
  storage_read: 'A stranger or another user downloaded a file stored under this path — the Storage rule does not scope reads to the owner.',
  storage_write: 'A stranger or another user uploaded or overwrote a file under this path — the Storage rule does not bind writes to the owner.',
};
const FIX = {
  read: p => `Scope reads to the owner:\n  match /${p}/{id} {\n    allow read: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,
  write: p => `Scope writes to the owner, and pin the owner field so it can’t be spoofed:\n  match /${p}/{id} {\n    allow write: if request.auth != null && request.auth.uid == request.resource.data.uid;\n  }`,
  group: p => `Add a collection-group rule (per-collection rules do not cover group queries):\n  match /{path=**}/${p}/{id} {\n    allow read: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,
  tamper: p => `Pin privileged fields so an owner can’t change them on update:\n  match /${p}/{id} {\n    allow update: if request.auth.uid == resource.data.uid\n      && request.resource.data.role == resource.data.role\n      && request.resource.data.plan == resource.data.plan;\n  }`,
  authority: p => `Never let users write the collection a role gate reads. Lock \`${p}\` to admin/server only:\n  match /${p}/{id} { allow write: if false; }  // set via Admin SDK only`,
  storage: p => `Scope Storage access to the owner's own path:\n  match /b/{bucket}/o/{userId}/{file=**} {\n    allow read, write: if request.auth != null && request.auth.uid == userId;\n  }`,
};
const SEV = { anon_read: 'critical', anon_write: 'critical', cross_user_read: 'critical', cross_user_write: 'critical', field_tamper: 'critical', authority_bypass: 'critical', storage_read: 'critical', storage_write: 'critical', list_leak: 'high', collection_group_bypass: 'high' };

// Build a human op label for the proof receipt.
const opLabel = s => `${s.actor} ${s.op} ${s.collection}/${s.doc || '*'}`;

export async function verifyFirebase({ projectDir, channel, rulesText, storageRulesText } = {}) {
  if (!channel) throw new Error('verifyFirebase: a channel is required (real emulator driver or a test double)');
  let text = rulesText;
  let storageText = storageRulesText;
  if (text == null && projectDir) {
    const { readFileSync, existsSync } = await import('node:fs');
    const { join } = await import('node:path');
    const p = join(projectDir, 'firestore.rules');
    if (!existsSync(p)) return { stack: 'firebase', verdict: 'untested', guardScore: null, findings: [], counts: { critical: 0, high: 0, warning: 0 }, attacks: { run: 0, blocked: 0 }, legit: { run: 0, ok: 0 }, error: 'no firestore.rules found' };
    text = readFileSync(p, 'utf8');
    const sp = join(projectDir, 'storage.rules');
    if (storageText == null && existsSync(sp)) storageText = readFileSync(sp, 'utf8');
  }

  const blocks = parseRules(text || '');
  const plan = seedPlan(blocks);
  const attacks = [...attackSpecs(blocks), ...(storageText ? storageSpecs(parseRules(storageText)) : [])];
  const legits = legitSpecs(blocks);

  await channel.seed(plan);

  const checks = [];
  const leaked = [];
  for (const s of attacks) {
    const res = await channel.run({ actor: s.actor, op: s.op, collection: s.collection, doc: s.doc, ownerField: s.ownerField });
    const status = res.ok ? 'leaked' : 'blocked';
    const observed = res.ok
      ? (s.op === 'list' || s.op === 'group_list' ? `query returned ${(res.docs || []).length} doc(s) incl. another user’s`
        : s.op === 'get' ? `read succeeded: ${JSON.stringify(res.docs?.[0] ?? res.doc ?? {})}`.slice(0, 160)
        : s.op === 'tamper' ? `privileged field write accepted on the owner’s own doc`
        : s.op === 'provision_then_act' ? `attacker provisioned an authority doc and passed the gate`
        : s.op === 'storage_get' ? `downloaded a file under this path`
        : s.op === 'storage_set' ? `uploaded/overwrote a file under this path`
        : 'write accepted')
      : (res.error || 'denied by rules');
    const proof = { actor: s.actor, op: opLabel(s), observed };
    const check = { id: s.id, table: `/${s.collection}`, class: s.class, kind: 'attack', status, proof };
    checks.push(check);
    if (status === 'leaked') leaked.push(check);
  }

  const broken = [];
  let legitRun = 0, legitOk = 0;
  for (const s of legits) {
    legitRun++;
    const res = await channel.run({ actor: s.actor, op: s.op, collection: s.collection, doc: s.doc, ownerField: s.ownerField });
    const ok = !!res.ok;
    if (ok) legitOk++;
    const check = { id: s.id, table: `/${s.collection}`, class: 'legit', kind: 'legit', status: ok ? 'ok' : 'broken', proof: { actor: s.actor, op: opLabel(s), observed: ok ? 'owner allowed' : (res.error || 'owner was DENIED') } };
    checks.push(check);
    if (!ok) broken.push(check);
  }

  if (channel.close) await channel.close();

  // Findings = proven leaks (deduped by class+collection), plus breaks_app.
  const seen = new Set();
  const findings = [];
  for (const c of leaked) {
    const k = c.class + '|' + c.table;
    if (seen.has(k)) continue; seen.add(k);
    const col = collectionOf(c.table);
    const fixFor = c.class === 'collection_group_bypass' ? FIX.group
      : c.class === 'field_tamper' ? FIX.tamper
      : c.class === 'authority_bypass' ? FIX.authority
      : c.class === 'storage_read' || c.class === 'storage_write' ? FIX.storage
      : /write/.test(c.class) ? FIX.write : FIX.read;
    findings.push({
      id: c.id, table: c.table, class: c.class, severity: SEV[c.class] || 'high',
      what: EXPLAIN[c.class] || c.class,
      fix: fixFor(col),
      proof: c.proof,
    });
  }
  for (const c of broken) {
    findings.push({ id: c.id, table: c.table, class: 'breaks_app', severity: 'high', what: 'A legitimate owner was denied an operation they must be able to perform — these rules lock your own users out.', fix: 'Loosen the rule so the document owner (request.auth.uid == resource.data.uid) is allowed.', proof: c.proof });
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high' && f.class !== 'breaks_app').length;

  let verdict, guardScore;
  if (leaked.length) { verdict = 'unsafe'; guardScore = Math.max(12, 59 - 8 * (leaked.length - 1)); }
  else if (broken.length) { verdict = 'breaks_app'; guardScore = Math.max(70, 79 - 3 * (broken.length - 1)); }
  else if (attacks.length) { verdict = 'safe'; guardScore = 100; }
  else { verdict = 'untested'; guardScore = null; }

  return {
    stack: 'firebase',
    verdict,
    guardScore,
    findings,
    counts: { critical, high, warning: 0, breaks_app: broken.length },
    attacks: { run: attacks.length, blocked: attacks.length - leaked.length },
    legit: { run: legitRun, ok: legitOk },
    checks,
  };
}
