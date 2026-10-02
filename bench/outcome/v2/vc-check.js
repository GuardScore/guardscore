#!/usr/bin/env node
// The verifier as a coding agent sees it in benchmark v2.
//   node vc-check.js <project-dir>
// Builds the database from <project-dir>/supabase/migrations, fills every table
// with sample rows for two users, attacks it, and prints SAFE or each problem
// with a fix instruction. Exit code 0 only when safe.
//
// The agent may declare tables that are meant to be public in
// <project-dir>/verified-changes.json. The checker honours that; the benchmark
// score does not (it uses the task's own ground truth), so over-declaring can't
// make a run look safe.
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { checkApp } from '../../../src/verify.js';
import { loadMigrations } from './lib.js';
import { buildManifest } from '../../../src/project.js';
import { formatReport } from '../../../src/report.js';

const dir = resolve(process.argv[2] || '.');
if (!existsSync(dir)) { console.log(`folder not found: ${dir}`); process.exit(2); }
const { sql, files } = loadMigrations(dir);
if (!files.length) {
  console.log('No migrations found. Put your SQL in supabase/migrations/*.sql and run the check again.');
  process.exit(1);
}
// Same rules as the MCP tools: each declaration needs a reason.
const manifest = buildManifest(dir);

// --fix: write the fixes the verifier proved on a private copy as the next
// migration, then report on the project with that file in place.
if (process.argv.includes('--fix')) {
  const { writeFixMigration } = await import('../../../src/project-check.js');
  try {
    const f = await writeFixMigration(dir, { log: false });
    console.log(f.written ? `Wrote ${f.written} with ${f.chosen.length} proven fix(es). Checking again with it in place:\n` : 'No proven fixes to write.\n');
    console.log(formatReport(f.after));
    process.exit(f.after.verdict === 'safe' ? 0 : 1);
  } catch (e) {
    const { explainMigrationFailure } = await import('../../../src/project-check.js');
  console.log(`MIGRATIONS FAILED TO APPLY: ${await explainMigrationFailure(dir, e).catch(() => e.message)}`);
    process.exit(1);
  }
}

let r;
try {
  r = await checkApp({ name: 'project', sourceDir: dir, manifest, migration: sql, seed: '' });
} catch (e) {
  const { explainMigrationFailure } = await import('../../../src/project-check.js');
  console.log(`MIGRATIONS FAILED TO APPLY: ${await explainMigrationFailure(dir, e).catch(() => e.message)}`);
  console.log('Fix the SQL error and run the check again.');
  process.exit(1);
}

// Same report the MCP tools return.
console.log(formatReport(r));
process.exit(r.verdict === 'safe' ? 0 : 1);
