// The Firestore rules scanner behind the front door's Firebase engine. Same bar
// as the Supabase one: catch the slam-dunk holes, never false-alarm on a safe
// ruleset, and produce a Guard Score in the same shape.
import { firestoreScan } from '../web/firebase-scan.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

// open write → unsafe
const openW = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /users/{u} { allow read, write: if true; } } }`);
ok(openW.verdict === 'unsafe' && openW.findings.some(f => f.class === 'open_write'), 'allow write: if true → unsafe');

// owner-scoped → clean
const owner = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /notes/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.uid; } } }`);
ok(owner.verdict === 'clear' && !owner.findings.length, 'owner-scoped rule → clean');

// any-signed-in write → review (warning), not critical
const authed = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /posts/{id} { allow read: if true; allow write: if request.auth != null; } } }`);
ok(authed.findings.some(f => f.class === 'any_signed_in_write' && f.severity === 'warning'), 'any-signed-in write → warning');

// open read of a personal collection → critical; of a neutral one → warning
const readUsers = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /users/{u} { allow read: if true; allow write: if request.auth.uid == u; } } }`);
ok(readUsers.findings.some(f => f.class === 'open_read' && f.severity === 'critical'), 'open read of /users → critical');
const readCatalog = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /products/{p} { allow read: if true; allow write: if false; } } }`);
ok(readCatalog.findings.every(f => f.severity !== 'critical'), 'open read of /products → not critical');

// test mode → unsafe
const testMode = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 12, 31); } } }`);
ok(testMode.verdict === 'unsafe', 'test-mode timestamp rule → unsafe');

// a role/get-gated write is NOT flagged as any-signed-in
const gated = firestoreScan(`service cloud.firestore { match /databases/{db}/documents {
  match /orders/{id} { allow write: if request.auth != null && get(/databases/$(db)/documents/staff/$(request.auth.uid)).data.role == 'admin'; } } }`);
ok(!gated.findings.some(f => f.class === 'any_signed_in_write'), 'admin/get-gated write → not flagged');

console.log(fail ? `web-firebase-scan: ${fail} failed` : 'web-firebase-scan checks passed (Firestore rules scanner)');
process.exit(fail ? 1 : 0);
