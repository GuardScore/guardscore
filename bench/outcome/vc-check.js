#!/usr/bin/env node
// The verifier as a coding agent sees it in the benchmark's "with_verify" arm.
//   node vc-check.js --task <task-id> <migration.sql>
// Prints SAFE, or each problem with a fix instruction. Exit code 0 only when safe.
// The final benchmark score never trusts this output: every run is re-scored
// afterwards by score.js with the untouched gauntlet.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkApp } from '../../src/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const ti = args.indexOf('--task');
const taskId = ti >= 0 ? args[ti + 1] : undefined;
const file = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--task')[0];

if (!taskId || !file) {
  console.log('usage: node vc-check.js --task <task-id> <migration.sql>');
  process.exit(2);
}
const taskDir = join(here, 'tasks', taskId);
if (!existsSync(taskDir)) { console.log(`unknown task: ${taskId}`); process.exit(2); }
if (!existsSync(file)) { console.log(`file not found: ${file}`); process.exit(2); }

const task = JSON.parse(readFileSync(join(taskDir, 'task.json'), 'utf8'));
const app = { name: taskId, manifest: task.manifest, migration: readFileSync(resolve(file), 'utf8'), seed: readFileSync(join(taskDir, 'seed.sql'), 'utf8') };

let r;
try {
  r = await checkApp(app);
} catch (e) {
  console.log(`MIGRATION FAILED TO APPLY: ${e.message}`);
  console.log('Fix the SQL error and run the check again.');
  process.exit(1);
}

const gaps = r.notTested.length ? `\nNot tested (no sample data): ${r.notTested.join(', ')}.` : '';
if (r.verdict === 'safe') {
  console.log(`SAFE: all ${r.attacks.run} attacks blocked and all ${r.legit.run} real-user checks pass.${gaps}`);
  process.exit(0);
}
console.log(r.verdict === 'unsafe'
  ? `UNSAFE: ${r.attacks.leaked} of ${r.attacks.run} attacks succeeded.`
  : `BREAKS THE APP: security holds, but ${r.legit.broken} of ${r.legit.run} real-user checks fail.`);
for (const f of r.fixes) {
  console.log(`\n[${f.table}]`);
  for (const p of f.problems) console.log(`- ${p}`);
  console.log('Proof:');
  for (const id of f.findings) {
    const c = r.checks.find(x => x.id === id);
    console.log(`  ${c.proof.actor}: ${c.proof.sql.split('\n')[0].slice(0, 140)} -> ${JSON.stringify(c.proof.observed)}`);
  }
  console.log(`How to fix: ${f.prompt.split('\n').slice(1).join(' ')}`);
}
process.exit(1);
