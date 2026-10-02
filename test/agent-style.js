// Realistic agent-style migrations with no seed data: the automatic sample data
// must fill every fillable table, the secure apps must come out safe (no false
// alarms), and the planted slip in the CRM must be caught.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkApp } from '../src/verify.js';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'agent-style');
const cases = [
  { file: 'crm.sql', manifest: { sharedTables: ['profile'] }, verdict: 'unsafe', findingsOnly: ['invoice_items'] },
  // Looked secure until round-three review: a customer can create an order already marked paid.
  { file: 'store.sql', manifest: { publicTables: ['product', 'categor', 'review'], sharedTables: ['profile'] }, verdict: 'unsafe', findingsOnly: ['orders'] },
  { file: 'team.sql', manifest: { sharedTables: ['profile'] }, verdict: 'safe' },
  // A real Haiku run: it declared its share-token table public to get past the
  // check (declaring a table public must not make its secrets public), and an
  // admins policy that queries admins makes every notes query fail.
  { file: 'share_declared_public.sql', manifest: { publicTables: ['^public_links$'], sharedTables: [] }, verdict: 'unsafe', findingsOnly: ['moderation_logs', 'notes', 'public_links'], notTested: ['admins'] },
];
let failures = 0;
const fail = m => { failures++; console.log(`  FAIL ${m}`); };
for (const c of cases) {
  const r = await checkApp({ name: c.file, manifest: c.manifest, migration: readFileSync(join(dir, c.file), 'utf8'), seed: '' });
  const tables = [...new Set(r.findings.map(f => f.table))];
  console.log(`${c.file}: ${r.verdict} (${r.guardScore}), attacks ${r.attacks.blocked}/${r.attacks.run} blocked, legit ${r.legit.ok}/${r.legit.run}, filled [${r.fixtures.filled.join(', ')}], not tested [${r.notTested.join(', ')}], inconclusive ${r.inconclusive}`);
  if (r.verdict !== c.verdict) fail(`${c.file}: verdict ${r.verdict}, expected ${c.verdict}`);
  if (r.fixtures.failed.length) fail(`${c.file}: sample data failed: ${JSON.stringify(r.fixtures.failed)}`);
  if (c.findingsOnly && tables.join() !== c.findingsOnly.join()) fail(`${c.file}: findings on [${tables}], expected [${c.findingsOnly}]`);
  if ((c.notTested || []).join() !== r.notTested.join()) fail(`${c.file}: not tested [${r.notTested}], expected [${c.notTested || []}]`);
}
console.log(failures ? `${failures} failure(s)` : 'agent-style checks passed');
process.exit(failures ? 1 : 0);
