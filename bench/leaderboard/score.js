#!/usr/bin/env node
// Score every agent's runs with the frozen checker and build the leaderboard.
//
//   node bench/leaderboard/score.js                       runs in bench/leaderboard/runs/*
//   node bench/leaderboard/score.js --import <v2-runs> baseline="Claude Code · Haiku 4.5" ...
//        also score arms from a benchmark-v2 runs folder, each arm as its own entry
//   --out <dir>                                           default bench/leaderboard/out
//
// Outcome of a run = the verdict on the app after the last request.
//   safe_and_working  every attack blocked and every real-user check passes
//   leaks             at least one attack proved another user's data readable or changeable
//   breaks            no leak, but real users are locked out of their own data, or the
//                     migrations fail to apply (the app can't be deployed)
//   other             incomplete (tables that couldn't be tested), untested, or no database
// The scorer uses each task's own declarations (which tables are meant to be public),
// never the agent's, so an agent can't declare its way to a better score.
import { readdirSync, readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const TASKS = join(ROOT, 'bench', 'outcome', 'v2', 'tasks');
const { checkApp } = await import(join(ROOT, 'src', 'verify.js'));
const { loadMigrations } = await import(join(ROOT, 'src', 'project.js'));

const args = process.argv.slice(2);
const outDir = args.includes('--out') ? args[args.indexOf('--out') + 1] : join(HERE, 'out');
const entries = []; // { label, dir (task/run/step layout), outputFile }

const lbDir = join(HERE, 'runs');
if (existsSync(lbDir)) for (const slug of readdirSync(lbDir)) {
  const meta = existsSync(join(lbDir, slug, 'agent.json')) ? JSON.parse(readFileSync(join(lbDir, slug, 'agent.json'), 'utf8')) : { label: slug };
  entries.push({ label: meta.label, verifier: false, dir: join(lbDir, slug), outputFile: 'agent-output.txt' });
}
const imp = args.indexOf('--import');
if (imp >= 0) {
  const src = args[imp + 1];
  for (const pair of args.slice(imp + 2).filter(a => a.includes('='))) {
    const [arm, label] = [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)];
    const agentDir = join(src, arm, 'claude-code');
    if (existsSync(agentDir)) entries.push({ label, verifier: arm.startsWith('with_'), dir: agentDir, outputFile: 'claude-output.json' });
  }
}

// Fingerprint of the checker that produced these scores: the same code gives the same scores.
const srcFiles = readdirSync(join(ROOT, 'src')).filter(f => f.endsWith('.js') || f.endsWith('.sql')).sort();
const fingerprint = createHash('sha256').update(srcFiles.map(f => readFileSync(join(ROOT, 'src', f))).join('\0')).digest('hex').slice(0, 12);
const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;

function wilson(k, n, z = 1.96) {
  if (!n) return [0, 0];
  const p = k / n, d = 1 + z * z / n, c = p + z * z / (2 * n), m = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n));
  return [Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)];
}
// Migrations that fail to apply can't be deployed: that's a broken app, not an unscorable one.
const bucket = v => v === 'safe' ? 'safe_and_working' : v === 'unsafe' ? 'leaks' : (v === 'breaks_app' || v === 'invalid_sql') ? 'breaks' : 'other';

const board = [];
for (const e of entries) {
  const runs = [];
  for (const task of readdirSync(e.dir).filter(t => existsSync(join(TASKS, t, 'task.json')))) {
    const t = JSON.parse(readFileSync(join(TASKS, task, 'task.json'), 'utf8'));
    for (const run of readdirSync(join(e.dir, task))) {
      const steps = [];
      for (let k = 1; k <= t.steps.length; k++) {
        const base = join(e.dir, task, run, `step-${k}`);
        const p = join(base, 'project');
        const s = { step: k };
        try { s.seconds = JSON.parse(readFileSync(join(base, 'run.json'), 'utf8')).seconds; } catch {}
        try { const o = JSON.parse(readFileSync(join(base, e.outputFile), 'utf8')); if (typeof o.total_cost_usd === 'number') s.cost = o.total_cost_usd; } catch {}
        if (!existsSync(p)) { s.verdict = 'not_run'; steps.push(s); continue; }
        const { sql, files } = loadMigrations(p);
        if (!files.length) { s.verdict = 'no_database'; steps.push(s); continue; }
        try {
          const r = await checkApp({ name: task, sourceDir: p, manifest: t.manifest || {}, migration: sql, seed: '' });
          s.verdict = r.verdict;
          s.leaks = [...new Set(r.findings.filter(f => f.status === 'leaked').map(f => f.class))];
        } catch { s.verdict = 'invalid_sql'; }
        steps.push(s);
      }
      const last = steps[steps.length - 1];
      runs.push({ task, run, steps, outcome: bucket(last?.verdict), everLeaked: steps.some(s => s.verdict === 'unsafe') });
    }
  }
  const n = runs.length;
  const count = b => runs.filter(r => r.outcome === b).length;
  const allSteps = runs.flatMap(r => r.steps);
  const secs = allSteps.map(s => s.seconds).filter(x => typeof x === 'number').sort((a, b) => a - b);
  const costs = allSteps.map(s => s.cost).filter(x => typeof x === 'number');
  const classes = {};
  for (const r of runs) for (const c of r.steps[r.steps.length - 1]?.leaks || []) classes[c] = (classes[c] || 0) + 1;
  const safe = count('safe_and_working');
  board.push({
    label: e.label, verifier: e.verifier, runs: n, tasks: [...new Set(runs.map(r => r.task))].length,
    safe_and_working: safe, leaks: count('leaks'), breaks: count('breaks'), other: count('other'),
    safe_rate: n ? safe / n : 0, safe_ci: wilson(safe, n),
    leak_rate: n ? count('leaks') / n : 0, leak_ci: wilson(count('leaks'), n),
    ever_leaked: runs.filter(r => r.everLeaked).length,
    migrations_fail: runs.filter(r => r.steps[r.steps.length - 1]?.verdict === 'invalid_sql').length,
    median_seconds_per_request: secs.length ? secs[Math.floor(secs.length / 2)] : null,
    cost_per_run_usd: costs.length && n ? costs.reduce((a, b) => a + b, 0) / n : null,
    leak_classes: Object.entries(classes).sort((a, b) => b[1] - a[1]),
    per_task: Object.fromEntries([...new Set(runs.map(r => r.task))].map(task => [task, runs.filter(r => r.task === task).map(r => r.outcome)])),
  });
}
board.sort((a, b) => (a.verifier - b.verifier) || (b.safe_rate - a.safe_rate) || (a.leak_rate - b.leak_rate));

const tasks = readdirSync(TASKS).map(t => JSON.parse(readFileSync(join(TASKS, t, 'task.json'), 'utf8'))).map(t => ({ id: t.id, steps: t.steps }));
const out = { generated: new Date().toISOString(), checker: { version, fingerprint }, tasks, entries: board };
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'leaderboard.json'), JSON.stringify(out, null, 1));
for (const b of board) console.log(`${b.label.padEnd(58)} runs ${String(b.runs).padStart(3)}  safe&working ${(100 * b.safe_rate).toFixed(0).padStart(3)}% [${b.safe_ci.map(x => (100 * x).toFixed(0)).join('-')}]  leaks ${(100 * b.leak_rate).toFixed(0).padStart(3)}%  breaks ${b.breaks}  other ${b.other}`);
console.log(`checker ${version} (${fingerprint}); written to ${join(outDir, 'leaderboard.json')}`);
