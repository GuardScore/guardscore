// Dry run of the remote path on local Postgres: runs every app's SQL bundle
// through vc.probe exactly as Supabase would receive it, then checks the scored
// results match the local gauntlet with zero differences.
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { loadApp } from '../src/verify.js';
import { plan, bundleSql, score, SETUP_SQL } from '../src/remote.js';
import { neutralizeExtensions, newEngine } from '../src/db.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const shim = readFileSync(join(root, 'src', 'shim.sql'), 'utf8');
const db = newEngine();
await db.exec(shim);
await db.exec(SETUP_SQL);
let bad = 0;
for (const name of readdirSync(join(root, 'apps')).sort()) {
  const app = loadApp(join(root, 'apps', name));
  const p = await plan(app);
  const res = await db.exec(neutralizeExtensions(bundleSql(app, p.specs, p.fixtureSql))); // same database reused, like the real project
  const results = res.at(-1).rows[0].results;
  const s = score(p, results);
  console.log(`${name}: local ${s.localSummary.verdict} (${s.localSummary.guardScore}), bundle ${s.summary.verdict} (${s.summary.guardScore}), ${s.diffs.length} differences`);
  for (const d of s.diffs) console.log('  ', d);
  if (s.diffs.length) bad++;
}
console.log(bad ? `${bad} app(s) differ` : 'bundle path matches local gauntlet for every app');
process.exit(bad ? 1 : 0);
