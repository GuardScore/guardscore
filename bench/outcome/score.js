// Outcome benchmark scorer.
//
// Reads agent output from either layout:
//   runs/<arm>/<agent>/<task>/migration.sql            (one run)
//   runs/<arm>/<agent>/<task>/<run>/migration.sql      (repeated runs)
// Arms: "baseline" (agent alone) and "with_verify" (agent calls the verifier
// before finishing). Every run is re-scored here with the untouched gauntlet;
// nothing the agent said about its own result counts.
//
//   node bench/outcome/score.js [runs-dir]
import { readdirSync, readFileSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkApp } from '../../src/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const tasksDir = join(here, 'tasks');
const runsDir = process.argv[2] || join(here, 'runs');
const dirs = p => (existsSync(p) ? readdirSync(p).filter(d => statSync(join(p, d)).isDirectory()).sort() : []);
const readJson = p => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };

const tasks = Object.fromEntries(dirs(tasksDir).map(id => [id, {
  ...JSON.parse(readFileSync(join(tasksDir, id, 'task.json'), 'utf8')),
  seed: readFileSync(join(tasksDir, id, 'seed.sql'), 'utf8'),
}]));

// Each run directory holds migration.sql (or NO_MIGRATION) plus optional agent metadata.
function runDirsFor(taskPath) {
  if (existsSync(join(taskPath, 'migration.sql')) || existsSync(join(taskPath, 'NO_MIGRATION'))) return [{ run: '1', path: taskPath }];
  return dirs(taskPath).map(run => ({ run, path: join(taskPath, run) }));
}

const results = [];
for (const arm of dirs(runsDir)) {
  for (const agent of dirs(join(runsDir, arm))) {
    for (const taskId of dirs(join(runsDir, arm, agent))) {
      const task = tasks[taskId];
      if (!task) continue;
      for (const { run, path } of runDirsFor(join(runsDir, arm, agent, taskId))) {
        const meta = readJson(join(path, 'claude-output.json')) || {};
        const timing = readJson(join(path, 'run.json')) || {};
        const row = { arm, agent, task: taskId, run, verdict: '', score: null, classes: '', turns: meta.num_turns ?? null, seconds: timing.seconds ?? null };
        const file = join(path, 'migration.sql');
        if (!existsSync(file)) {
          row.verdict = 'no_output';
        } else {
          const app = { name: `${agent}/${taskId}/${run}`, manifest: task.manifest, migration: readFileSync(file, 'utf8'), seed: task.seed };
          try {
            const r = await checkApp(app);
            row.verdict = r.verdict;
            row.score = r.guardScore;
            row.classes = [...new Set(r.findings.map(f => f.class))].join(' ');
            if (r.notTested.length) row.classes = `${row.classes} [not tested: ${r.notTested.join(', ')}]`.trim();
          } catch (e) {
            // Failed to load locally. Could be a real SQL error, or a Supabase
            // feature the local copy lacks: re-check these on real Supabase.
            row.verdict = 'invalid';
            row.classes = e.message.slice(0, 100);
          }
        }
        results.push(row);
      }
    }
  }
}

if (!results.length) {
  console.log(`No runs found in ${runsDir}.`);
  process.exit(0);
}

console.table(results.map(({ arm, agent, task, run, verdict, score, classes }) => ({ arm, agent, task, run, verdict, score, classes })));

const groups = new Map();
for (const r of results) {
  const k = `${r.agent} | ${r.arm}`;
  if (!groups.has(k)) groups.set(k, { runs: 0, unsafe: 0, breaks_app: 0, safe: 0, invalid: 0, no_output: 0, turns: [], seconds: [] });
  const g = groups.get(k);
  g.runs++;
  g[r.verdict] = (g[r.verdict] || 0) + 1;
  if (r.turns != null) g.turns.push(r.turns);
  if (r.seconds != null) g.seconds.push(r.seconds);
}
const median = a => (a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : null);
const pct = (n, d) => (d ? `${Math.round(100 * n / d)}%` : 'n/a');
const summary = [...groups].map(([k, g]) => {
  const scored = g.runs - g.invalid - g.no_output;
  return {
    'agent | arm': k,
    runs: g.runs,
    safe: g.safe,
    unsafe: g.unsafe,
    'breaks app': g.breaks_app,
    invalid: g.invalid,
    'no output': g.no_output,
    'unsafe rate (of scored)': pct(g.unsafe, scored),
    'median turns': median(g.turns),
    'median seconds': median(g.seconds),
  };
});
console.log('\nPer agent and arm');
console.table(summary);

const invalid = results.filter(r => r.verdict === 'invalid');
if (invalid.length) {
  console.log(`\n${invalid.length} run(s) failed to load locally. Re-check them on real Supabase before counting them as agent errors:`);
  for (const r of invalid) console.log(`  ${r.arm}/${r.agent}/${r.task}/${r.run}: ${r.classes}`);
}
writeFileSync(join(runsDir, 'scores.json'), JSON.stringify({ results, summary }, null, 2));
console.log(`\nSaved ${join(runsDir, 'scores.json')}`);
