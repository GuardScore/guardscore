// Regression suite from five rounds of independent security review (2026-09-24/25):
// 72 apps built by an AI agent (plus one policy case), re-judged by reviewer agents that never saw the
// checker's code and tested their claims in their own database. Each case pins
// the verdict and the findings the reviewers confirmed (must), and the false
// alarms they caught (mustNot). One case stays disputed:
// r2b_case01 (a shared-note lookup that ignores the key: we call it unsafe,
// the reviewer broken). Round three audited apps the checker called SAFE; one
// miss is pinned as a known gap: r3a_case06, where team policies require an
// "admin" role the table's check never allows, so owners can't manage members.
// Round four audited apps after the verifier's own fixes; three known gaps are
// pinned as today's behaviour: r4_case02 (existing users can't accept an
// invitation), r4_case08 (no policy shows published
// recipes, which only the task text says is wanted).
// Round five: reviewers split on attaching rows to another user's item when
// ids are random uuids (r5a_case01/05/07/08 say unsafe, earlier rounds said a
// weakness). The checker reports it as a notice and a leak only with guessable
// ids; r5b_case01 (anonymous visitors reading usernames of a signed-in-only
// profiles table) and r5b_case08 (published recipes shown to signed-in users
// only) are pinned the same way. vc_account_tenant (one account per user) and
// vc_purchase_trigger (reviews need a purchase) pin sample-data coverage;
// vc_loosened_insert pins an agent loosening inserts to fit the test data;
// vc_trigger_role_conflict pins a creator trigger writing a role the table no longer allows.
// case16 was "incomplete" until owners were read from policies (auth.uid() = id);
// now proven broken: a new user can never create the users row every habit needs. Decision (2026-09-25): a uuid attach is a leak
// when B can read the item id anywhere (vc_attach_seen), a notice otherwise.
import { checkApp } from '../src/verify.js';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = join(dirname(fileURLToPath(import.meta.url)), 'review');
const cases = JSON.parse(readFileSync(join(here, 'expected.json'), 'utf8'));
let failures = 0;
for (const c of cases) {
  const dir = join(here, c.case, 'migrations');
  const sql = readdirSync(dir).sort().map(f => readFileSync(join(dir, f), 'utf8')).join('\n');
  const r = await checkApp({ name: c.case, manifest: c.manifest, migration: sql, seed: '' });
  const found = new Set(r.findings.filter(f => f.status === 'leaked').map(f => `${f.table}:${f.class}`));
  const bad = [];
  if (r.verdict !== c.verdict) bad.push(`verdict ${r.verdict}, expected ${c.verdict}`);
  for (const m of c.must) if (!found.has(m)) bad.push(`missed ${m}`);
  for (const m of c.mustNot) if (found.has(m)) bad.push(`false alarm ${m}`);
  if (bad.length) { failures++; console.log(`  FAIL ${c.case}: ${bad.join('; ')}`); }
}
console.log(failures ? `${failures} review case(s) failed` : `review regression checks passed (${cases.length} cases)`);
process.exit(failures ? 1 : 0);
