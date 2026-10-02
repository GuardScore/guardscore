// The warm engine must give exactly the same results as a fresh engine, and a
// migration that commits on its own must not leak into the next check.
import { readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadApp, checkApp } from '../src/verify.js';
import { buildDb } from '../src/db.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const fail = m => { failures++; console.log(`  FAIL ${m}`); };
const sig = r => JSON.stringify([r.verdict, r.guardScore, r.checks.map(c => [c.id, c.status])]);

for (const name of readdirSync(join(root, 'apps')).sort()) {
  const app = loadApp(join(root, 'apps', name));
  process.env.VC_FRESH_DB = '1';
  const fresh = await checkApp(app);
  delete process.env.VC_FRESH_DB;
  const warm = await checkApp(app);
  if (sig(fresh) !== sig(warm)) fail(`${name}: warm result differs from fresh`);
}
console.log('warm = fresh on every seeded app');

// A migration with its own transaction control.
const committing = {
  name: 'committing', manifest: {}, seed: '',
  migration: `begin;
create table public.leaky (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users, body text not null);
alter table public.leaky enable row level security;
create policy own on public.leaky for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
commit;`,
};
const r = await checkApp(committing);
if (r.verdict !== 'safe' || r.inconclusive) fail(`committing migration: ${r.verdict}, inconclusive ${r.inconclusive}`);
const next = await buildDb({ migrations: [''] });
const left = (await next.query(`select count(*)::int as n from pg_tables where schemaname = 'public'`)).rows[0].n;
await next.close();
if (left !== 0) fail(`${left} table(s) leaked into the next check`);
console.log(`migration with its own commit: ${r.verdict}, nothing leaked into the next check`);

// Bad SQL still reports the real error.
try { await checkApp({ name: 'bad', manifest: {}, seed: '', migration: 'create table oops (' }); fail('bad SQL accepted'); }
catch (e) { console.log(`bad SQL: "${e.message}"`); }

console.log(failures ? `${failures} failure(s)` : 'warm engine checks passed');
process.exit(failures ? 1 : 0);
