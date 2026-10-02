// Firebase engine: the attack/grade/score/proof pipeline (src/firebase/verify.js)
// and the rules planner (src/firebase/rules.js) are unit-tested here WITHOUT a
// live emulator, via test-double channels that simulate a backend honouring the
// rules. The real emulator binding (src/firebase/emulator.js) is a thin REST
// layer exercised on a host with firebase-tools + Java (see docs/firebase-engine.md).

import { parseRules, collectionOf, ownerFieldOf, attackSpecs, legitSpecs, seedPlan, subCollectionOf, authorityGates, storageSpecs } from '../src/firebase/rules.js';
import { verifyFirebase } from '../src/firebase/verify.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

/* ---------- rules planner (pure) ---------- */
const RULES_LEAK = `service cloud.firestore { match /databases/{db}/documents {
  match /users/{userId} { allow read, write: if true; }
}}`;
const RULES_SAFE = `service cloud.firestore { match /databases/{db}/documents {
  match /notes/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.uid; }
}}`;
const RULES_LOCKED = `service cloud.firestore { match /databases/{db}/documents {
  match /notes/{id} { allow read, write: if false; }
}}`;

const allBlocks = parseRules(RULES_SAFE);
const b = allBlocks.filter(x => x.allows.length); // drop the /databases/{db}/documents wrapper (no allows)
ok(b.length === 1 && collectionOf(b[0].path) === 'notes', 'parse + collectionOf (wrapper block ignored)');
ok(ownerFieldOf('request.auth.uid == resource.data.uid') === 'uid', 'ownerFieldOf reads owner field');
ok(attackSpecs(b).some(s => s.class === 'cross_user_read') && attackSpecs(b).some(s => s.class === 'cross_user_write'), 'enumerates cross-user read+write attacks');
ok(attackSpecs(b).some(s => s.class === 'list_leak'), 'enumerates a list-leak attack');
ok(legitSpecs(b).length >= 2, 'enumerates victim legit read+write');
ok(seedPlan(b).docs.some(d => d.owner === 'victim') && seedPlan(b).docs.some(d => d.owner === 'attacker'), 'seed plan plants both actors');

/* ---------- Milestone 2: scanner-beating classes (planner) ---------- */
const RULES_M2 = `service cloud.firestore { match /databases/{db}/documents {
  match /users/{u}/notes/{n} { allow read: if request.auth != null; }
  match /profiles/{id} { allow update: if request.auth.uid == resource.data.uid; }
  match /orders/{id} { allow read: if get(/databases/$(db)/documents/staff/$(request.auth.uid)).data.role == 'admin'; }
  match /staff/{id} { allow write: if request.auth != null; }
}}`;
const m2 = parseRules(RULES_M2);
ok(subCollectionOf('/users/{u}/notes/{n}') === 'notes', 'subCollectionOf finds the group-query target');
ok(authorityGates(m2).includes('staff'), 'authorityGates flags an attacker-writable role gate');
const m2classes = new Set(attackSpecs(m2).map(s => s.class));
ok(m2classes.has('collection_group_bypass'), 'enumerates collection-group bypass');
ok(m2classes.has('field_tamper'), 'enumerates field tamper');
ok(m2classes.has('authority_bypass'), 'enumerates authority-gate bypass');

/* ---------- test-double channels ---------- */
const withDocs = op => (op === 'list' || op === 'group_list') ? { ok: true, docs: [{ uid: 'victim' }, { uid: 'attacker' }] } : op === 'get' ? { ok: true, docs: [{ uid: 'victim' }] } : { ok: true };
const allowAll = { async seed() {}, async run({ op }) { return withDocs(op); } };
// A genuinely safe backend: the owner can do their own read/write, but privileged-field
// tampering is pinned (denied) and cross-actor ops are denied.
const ownerOnly = { async seed() {}, async run({ actor, op }) { return (actor === 'victim' && op !== 'tamper') ? withDocs(op) : { ok: false, error: 'denied by rules' }; } };
const denyAll = { async seed() {}, async run() { return { ok: false, error: 'denied by rules' }; } };

/* ---------- scenario 1: wide-open rules → unsafe, capped ≤59, with proof ---------- */
const leak = await verifyFirebase({ rulesText: RULES_LEAK, channel: allowAll });
ok(leak.verdict === 'unsafe', 'open rules → unsafe');
ok(leak.guardScore <= 59, `open rules → Guard Score capped ≤59 (got ${leak.guardScore})`);
ok(leak.findings.some(f => f.class === 'anon_read' || f.class === 'cross_user_read'), 'reports a read leak');
ok(leak.findings.every(f => f.proof && f.proof.actor && f.proof.op && f.proof.observed), 'every finding carries a proof receipt {actor, op, observed}');
ok(leak.attacks.blocked < leak.attacks.run, 'not all attacks were blocked');

/* ---------- scenario 2: owner-scoped rules → safe, 100 ---------- */
const safe = await verifyFirebase({ rulesText: RULES_SAFE, channel: ownerOnly });
ok(safe.verdict === 'safe', `owner-scoped rules → safe (got ${safe.verdict})`);
ok(safe.guardScore === 100, `owner-scoped rules → 100 (got ${safe.guardScore})`);
ok(safe.legit.ok === safe.legit.run && safe.legit.run > 0, 'owner can still do their own ops');
ok(!safe.findings.length, 'no findings on a safe ruleset');

/* ---------- scenario 3: locked-out rules → breaks_app, ≤79 ---------- */
const locked = await verifyFirebase({ rulesText: RULES_LOCKED, channel: denyAll });
ok(locked.verdict === 'breaks_app', `deny-all rules → breaks_app (got ${locked.verdict})`);
ok(locked.guardScore <= 79, `deny-all rules → capped ≤79 (got ${locked.guardScore})`);
ok(locked.findings.some(f => f.class === 'breaks_app'), 'reports a breaks_app finding');

/* ---------- scenario 4: M2 classes proven through the pipeline, with receipts ---------- */
const m2run = await verifyFirebase({ rulesText: RULES_M2, channel: allowAll });
const m2found = new Set(m2run.findings.map(f => f.class));
ok(m2run.verdict === 'unsafe', 'M2 rules attacked → unsafe');
ok(m2found.has('field_tamper') && m2found.has('collection_group_bypass') && m2found.has('authority_bypass'), 'M2 findings: tamper + group bypass + authority bypass');
ok(m2run.findings.every(f => f.proof && f.proof.observed && f.fix), 'every M2 finding carries a proof receipt and a fix');

/* ---------- scenario 5: Storage attacks ---------- */
const STORAGE_RULES = `rules_version = '2';
service firebase.storage { match /b/{bucket}/o {
  match /public/{f=**} { allow read: if true; allow write: if false; }
  match /uploads/{f=**} { allow read, write: if true; }
}}`;
const sspecs = storageSpecs(parseRules(STORAGE_RULES));
ok(sspecs.some(s => s.class === 'storage_write') && sspecs.some(s => s.class === 'storage_read'), 'enumerates storage read + write attacks');
const storeRun = await verifyFirebase({ rulesText: RULES_SAFE, storageRulesText: STORAGE_RULES, channel: allowAll });
ok(storeRun.findings.some(f => f.class === 'storage_write'), 'proves a storage write leak through the pipeline');
ok(storeRun.findings.filter(f => /storage/.test(f.class)).every(f => f.fix && f.proof), 'storage findings carry a fix + proof');

console.log(fail ? `firebase-engine: ${fail} failed` : 'firebase-engine checks passed (planner + M1/M2 + storage + grade/score/proof pipeline)');
process.exit(fail ? 1 : 0);
