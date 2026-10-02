// Head-to-head on the seeded apps: the deep check versus an existence check.
//
// The existence check re-implements the approach reported for early vibecoding
// scanners and basic database lints: a table is flagged only if RLS is off, or
// on with no policies. It is our re-implementation of that approach, not any
// vendor's actual tool. Real tools join this table as adapters are added.
import { readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadApp, checkApp } from '../src/verify.js';
import { buildDb } from '../src/db.js';
import { introspect } from '../src/introspect.js';

const appsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'apps');

async function existenceCheck(app) {
  const db = await buildDb({ migrations: [app.migration], seed: app.seed });
  try {
    const schema = await introspect(db, app.manifest);
    const flagged = schema.filter(t => !t.rls || t.policyCount === 0).map(t => t.name);
    const storagePolicies = (await db.query(`select count(*)::int as n from pg_policies where schemaname = 'storage'`)).rows[0].n;
    const hasObjects = (await db.query(`select count(*)::int as n from storage.objects`)).rows[0].n > 0;
    if (hasObjects && storagePolicies === 0) flagged.push('storage.objects');
    return flagged;
  } finally {
    await db.close();
  }
}

const rows = [];
const tally = { deep: { leaksCaught: 0, brokenCaught: 0, falseAlarms: 0 }, existence: { leaksCaught: 0, brokenCaught: 0, falseAlarms: 0 } };
let leakApps = 0, brokenApps = 0, safeApps = 0;

for (const name of readdirSync(appsDir).sort()) {
  const app = loadApp(join(appsDir, name));
  const truth = app.manifest.expect?.verdict;
  const deep = await checkApp(app);
  const ex = await existenceCheck(app);
  const deepFlags = deep.verdict !== 'safe';
  const exFlags = ex.length > 0;

  if (truth === 'unsafe') { leakApps++; if (deep.verdict === 'unsafe') tally.deep.leaksCaught++; if (exFlags) tally.existence.leaksCaught++; }
  if (truth === 'breaks_app') { brokenApps++; if (deep.verdict === 'breaks_app') tally.deep.brokenCaught++; }
  if (truth === 'safe') { safeApps++; if (deepFlags) tally.deep.falseAlarms++; if (exFlags) tally.existence.falseAlarms++; }

  rows.push({
    app: name,
    truth,
    'deep check': `${deep.verdict} (${deep.guardScore})`,
    'existence check': exFlags ? `flags ${ex.join(', ')}` : 'passes',
  });
}

console.table(rows);
console.log(`\nLeaking apps caught:   deep ${tally.deep.leaksCaught}/${leakApps}, existence ${tally.existence.leaksCaught}/${leakApps}`);
console.log(`Broken apps identified as broken (not leaking): deep ${tally.deep.brokenCaught}/${brokenApps}, existence n/a (flags it as a missing-policy risk)`);
console.log(`False alarms on secure apps: deep ${tally.deep.falseAlarms}/${safeApps}, existence ${tally.existence.falseAlarms}/${safeApps}`);
console.log('\nThese are seeded apps written to cover known failure classes, so this shows coverage, not real-world rates.');
console.log('Real-world rates come from the outcome benchmark (bench/outcome) once agent runs are collected.');
