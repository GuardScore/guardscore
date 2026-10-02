// Benchmark v2 scorer. Re-checks every step of every run with the untouched
// gauntlet, using the task's own ground truth for which tables are public (what
// the agent declared in verified-changes.json is ignored here).
//
//   node bench/outcome/v2/score.js [runs-dir]
//
// Layout: runs/<arm>/<agent>/<task>/<run>/step-<k>/{project/, claude-output.json, run.json}
import { readdirSync, readFileSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkApp } from '../../../src/verify.js';
import { loadMigrations } from './lib.js';

const here = dirname(fileURLToPath(import.meta.url));
const runsDir = process.argv[2] || join(here, 'runs');
const dirs = p => (existsSync(p) ? readdirSync(p).filter(d => statSync(join(p, d)).isDirectory()).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })) : []);
const readJson = p => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
const tasks = Object.fromEntries(dirs(join(here, 'tasks')).map(id => [id, readJson(join(here, 'tasks', id, 'task.json'))]));

const rows = [];
for (const arm of dirs(runsDir)) for (const agent of dirs(join(runsDir, arm))) for (const taskId of dirs(join(runsDir, arm, agent))) {
  const task = tasks[taskId];
  if (!task) continue;
  for (const run of dirs(join(runsDir, arm, agent, taskId))) {
    const runPath = join(runsDir, arm, agent, taskId, run);
    for (let k = 1; k <= task.steps.length; k++) {
      const stepPath = join(runPath, `step-${k}`);
      const row = { arm, agent, task: taskId, run, step: k, steps: task.steps.length, verdict: '', score: null, classes: '', notTested: '', layout: '', turns: null, seconds: null, cost: null };
      if (!existsSync(stepPath)) { row.verdict = 'not_run'; rows.push(row); continue; }
      const meta = readJson(join(stepPath, 'claude-output.json')) || {};
      row.turns = meta.num_turns ?? null;
      row.cost = meta.total_cost_usd ?? null;
      row.seconds = readJson(join(stepPath, 'run.json'))?.seconds ?? null;
      const proj = join(stepPath, 'project');
      const { sql, files, layout } = existsSync(proj) ? loadMigrations(proj) : { files: [], layout: 'none' };
      row.layout = layout;
      if (!files.length) { row.verdict = 'no_output'; rows.push(row); continue; }
      try {
        const r = await checkApp({ name: `${taskId}/${run}/${k}`, manifest: task.manifest || {}, migration: sql, seed: '' });
        row.verdict = r.verdict;
        row.score = r.guardScore;
        row.classes = [...new Set(r.findings.map(f => `${f.table}:${f.class}`))].join(' ');
        row.notTested = r.notTested.map(t => (r.missed.includes(t) ? `${t}(!)` : t)).join(' ');
      } catch (e) {
        row.verdict = 'invalid';
        row.classes = e.message.slice(0, 100);
      }
      rows.push(row);
    }
  }
}

if (!rows.length) { console.log(`No runs found in ${runsDir}.`); process.exit(0); }

console.log('Every step   (!) = could not be tested and was not skipped on purpose: "safe" is not claimed');
console.table(rows.map(({ arm, task, run, step, verdict, score, classes, notTested }) => ({ arm, task, run, step, verdict, score, classes, 'not tested': notTested })));

// One line per run: the verdict after the last request, and the first step that went unsafe.
const runs = new Map();
for (const r of rows) {
  const k = `${r.arm}|${r.agent}|${r.task}|${r.run}`;
  if (!runs.has(k)) runs.set(k, []);
  runs.get(k).push(r);
}
const perRun = [...runs.values()].map(steps => {
  const last = [...steps].reverse().find(s => s.verdict !== 'not_run') || steps.at(-1);
  const firstUnsafe = steps.find(s => s.verdict === 'unsafe');
  return {
    arm: steps[0].arm, agent: steps[0].agent, task: steps[0].task, run: steps[0].run,
    final: last.verdict, finalStep: `${last.step}/${last.steps}`,
    everUnsafe: !!firstUnsafe, firstUnsafeStep: firstUnsafe?.step ?? null,
    seconds: steps.reduce((a, s) => a + (s.seconds || 0), 0),
    cost: steps.every(s => s.cost == null) ? null : steps.reduce((a, s) => a + (s.cost || 0), 0),
  };
});

const median = a => (a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : null);
const pct = (n, d) => (d ? `${Math.round(100 * n / d)}%` : 'n/a');
const groups = new Map();
for (const r of perRun) {
  const k = `${r.agent} | ${r.arm}`;
  if (!groups.has(k)) groups.set(k, []);
  groups.get(k).push(r);
}
const summary = [...groups].map(([k, g]) => {
  const scored = g.filter(r => ['safe', 'unsafe', 'breaks_app'].includes(r.final));
  const count = v => g.filter(r => r.final === v).length;
  return {
    'agent | arm': k,
    runs: g.length,
    'safe at end': count('safe'),
    'unsafe at end': count('unsafe'),
    'breaks app at end': count('breaks_app'),
    'incomplete / untested at end': count('incomplete') + count('untested'),
    'invalid / no output': count('invalid') + count('no_output') + count('not_run'),
    'unsafe rate at end (of scored)': pct(count('unsafe'), scored.length),
    'unsafe at any step': pct(g.filter(r => r.everUnsafe).length, g.length),
    'median seconds per run': median(g.map(r => r.seconds)),
    'total cost (USD, if reported)': g.some(r => r.cost != null) ? Number(g.reduce((a, r) => a + (r.cost || 0), 0).toFixed(2)) : 'n/a',
  };
});
console.log('\nPer run');
console.table(perRun.map(({ arm, task, run, final, finalStep, firstUnsafeStep, seconds }) => ({ arm, task, run, final, 'after step': finalStep, 'first unsafe step': firstUnsafeStep, seconds })));
console.log('\nPer agent and arm');
console.table(summary);

const invalid = rows.filter(r => r.verdict === 'invalid');
if (invalid.length) {
  console.log(`\n${invalid.length} step(s) failed to load locally. Re-check them on real Supabase before counting them as agent errors:`);
  for (const r of invalid) console.log(`  ${r.arm}/${r.agent}/${r.task}/${r.run}/step-${r.step}: ${r.classes}`);
}
const other = rows.filter(r => r.layout === 'other .sql files');
if (other.length) console.log(`\n${other.length} step(s) had no supabase/migrations folder; their other .sql files were used instead.`);
writeFileSync(join(runsDir, 'scores.json'), JSON.stringify({ rows, perRun, summary }, null, 2));
console.log(`\nSaved ${join(runsDir, 'scores.json')}`);
