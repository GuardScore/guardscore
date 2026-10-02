#!/usr/bin/env node
// verified-changes command line.
//
//   verified-changes check  [project-dir]            check a Supabase project as it stands
//   verified-changes verify [project-dir] <change>   check one change (a migration file in the project, or --sql <file>)
//   verified-changes guard  [project-dir] -- <command...>
//                                                    run <command> (e.g. supabase db push) only if the check passes
//   verified-changes fix    [project-dir]            write the proven fixes as the next migration, then check again
//   verified-changes hook install [project-dir]      git pre-push hook: block pushes that make the database unsafe
//   verified-changes serve  [--port 8787]            HTTP API + the paste-your-schema web front door (see src/server.js)
//   verified-changes badge  [score] [--md] [--out f] a Guard Score badge to embed (SVG, or markdown with --md)
//   verified-changes audit  <receipt-dir>            verify a receipt log's chain and signatures
//   verified-changes map    [project-dir]            print a permission map: who can do what per table
//   verified-changes pgtap  [project-dir]            export the checks as a pgTAP regression suite (supabase test db)
//   verified-changes rules                           list every attack class the checker runs
//   verified-changes demo                            run a check on a bundled example app with planted holes
//   verified-changes snapshot [project-dir]          save the RLS/policy/grant state for later drift checks
//   verified-changes diff     [project-dir]          compare the project now against the saved snapshot
//   verified-changes scan-code [project-dir]         static scan of server code for payment/route/role risks
//   verified-changes check-firebase [project-dir]    static analysis of firestore.rules / storage.rules (first-version)
//   verified-changes check-postgres [project-dir]    attack a generic (non-Supabase) Postgres app with GUC-identity RLS
//   verified-changes secrets [project-dir]           scan source/config for leaked secrets (service_role/Stripe/AWS/…)
//   verified-changes watch   [project-dir]           re-check on change and report Guard Score drift over time
//   (check auto-detects the stack: Supabase migrations · firestore.rules · schema.prisma · generic Postgres RLS)
//
// Options for check/verify/guard:
//   --public "table: why it is public"    repeatable; same for --shared
//   --format text|json|markdown|sarif|html|badge|badge-md  default text (html = a Guard Score dashboard; badge = the SVG)
//   --out <file>                          write the output to a file and print a one-line summary
//   --out-dir <dir>                       write result.json, .md, .sarif and .txt at once (for CI)
//   --no-log                              don't write a signed receipt
//   --include-unproven                    (fix) also write fixes that weren't proven, marked for review
//   --live <postgres-url> | --live-dump <schema.sql> | --linked
//                                         check the deployed database instead of the migration files
//                                         (structure only, never rows) and list how they differ
// Exit codes: 0 safe, 1 not safe (unsafe, breaks the app, incomplete, untested), 2 error.
import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { checkProject, writeFixMigration, ProjectError, passed } from './project-check.js';
import { LiveError } from './live.js';
import { formatReport } from './report.js';
import { toMarkdown, toSarif, toHtml } from './formats.js';
import { renderResult } from './render.js';
import { badgeSvg, badgeMarkdown } from './badge.js';
import { auditLog } from './receipts.js';
import { loadApp, checkApp, verify } from './verify.js';

const argv = process.argv.slice(2);
const dd = argv.indexOf('--');
const args = dd >= 0 ? argv.slice(0, dd) : argv;
const tail = dd >= 0 ? argv.slice(dd + 1) : [];
const [cmd, ...rest] = args;
const WITH_VALUE = new Set(['--public', '--shared', '--format', '--out', '--out-dir', '--sql', '--port', '--log', '--live', '--live-dump', '--snapshot']);
const opts = {}, pos = [];
for (let i = 0; i < rest.length; i++) {
  const a = rest[i];
  if (WITH_VALUE.has(a)) (opts[a] ||= []).push(rest[++i]);
  else if (a.startsWith('--')) opts[a] = true;
  else pos.push(a);
}
const one = k => opts[k]?.[0];

function emit(kind, run, dir) {
  const r = run.result;
  const format = one('--format') || 'text';
  const body = format === 'json' ? JSON.stringify(r, null, 2)
    : format === 'markdown' ? toMarkdown(r, { kind })
    : format === 'sarif' ? JSON.stringify(toSarif(r, { dir, files: run.files }), null, 2)
    : format === 'html' ? toHtml(r, { app: dir.split('/').pop() })
    : format === 'badge' ? badgeSvg(r.guardScore)
    : format === 'badge-md' ? badgeMarkdown(r.guardScore)
    : formatReport(r, { kind });
  if (one('--out-dir')) {
    // Every format at once (CI): result.json, result.md, result.sarif, result.txt.
    const d = one('--out-dir'); mkdirSync(d, { recursive: true });
    writeFileSync(join(d, 'result.json'), JSON.stringify(r, null, 2));
    writeFileSync(join(d, 'result.md'), toMarkdown(r, { kind }));
    writeFileSync(join(d, 'result.sarif'), JSON.stringify(toSarif(r, { dir, files: run.files }), null, 2));
    writeFileSync(join(d, 'result.txt'), formatReport(r, { kind }));
    writeFileSync(join(d, 'dashboard.html'), toHtml(r, { app: dir.split('/').pop() }));
    writeFileSync(join(d, 'badge.svg'), badgeSvg(r.guardScore));
    console.log(`verified-changes: ${r.verdict}${r.guardScore != null ? ` (Guard Score ${r.guardScore})` : ''}; results in ${d}`);
  } else if (one('--out')) {
    writeFileSync(one('--out'), body);
    console.log(`verified-changes: ${r.verdict}${r.guardScore != null ? ` (Guard Score ${r.guardScore})` : ''}; ${format} written to ${one('--out')}`);
  } else console.log(body);
  return passed(r) ? 0 : 1;
}

async function runCheck(dir, change) {
  // --quick: only attack the tables that changed since the last snapshot, for a
  // fast re-check in CI. Falls back to a full check if there is no snapshot.
  let only;
  if (opts['--quick']) {
    const snapPath = one('--snapshot') || join(resolve(dir), '.verified-changes', 'snapshot.json');
    if (existsSync(snapPath)) {
      const { captureState, diffState } = await import('./parity.js');
      const { loadMigrations } = await import('./project.js');
      const changes = diffState(JSON.parse(readFileSync(snapPath, 'utf8')), await captureState(loadMigrations(resolve(dir)).sql));
      only = new Set(changes.map(c => c.table));
      if (!only.size) { console.log('quick check: nothing changed since the snapshot; skipping.'); process.exit(0); }
      console.error(`quick check: ${only.size} changed table(s): ${[...only].join(', ')}`);
    } else console.error('quick check: no snapshot found, running a full check.');
  }
  const run = await checkProject(dir, {
    public_tables: opts['--public'] || [], shared_tables: opts['--shared'] || [],
    change_file: change, change_sql: one('--sql') ? readFileSync(one('--sql'), 'utf8') : undefined,
    log: !opts['--no-log'], only,
    live: one('--live') || one('--live-dump') || opts['--linked'] ? { dbUrl: one('--live'), dump: one('--live-dump'), linked: !!opts['--linked'] } : undefined,
  });
  return run;
}

const isLegacyApp = d => existsSync(join(d, 'migration.sql')) && !existsSync(join(d, 'supabase'));

const HOOK = `#!/bin/sh
# verified-changes: block a push when the database migrations are unsafe.
# Runs only when supabase/migrations changed in the commits being pushed.
changed=$(git diff --name-only @{push}.. -- supabase/migrations 2>/dev/null || git diff --name-only HEAD~1.. -- supabase/migrations)
[ -z "$changed" ] && exit 0
npx --yes verified-changes check . --format text || {
  echo ""
  echo "verified-changes: push blocked. Fix the findings above (each comes with a proven fix), or push with --no-verify to skip."
  exit 1
}
`;

try {
  if (cmd === 'check' || cmd === 'verify' || cmd === 'guard') {
    const twoArgs = cmd === 'verify' ? pos.length >= 2 : pos.length >= 1;
    const dir = resolve(twoArgs ? pos[0] : '.');
    const change = cmd === 'verify' ? (twoArgs ? pos[1] : pos[0]) : undefined;
    // Stack auto-detection: a Firestore project (firestore.rules, no Supabase
    // migrations) routes to the Firebase engine so `check .` is one command for
    // any supported backend.
    if (cmd === 'check' && existsSync(join(dir, 'firestore.rules')) && !existsSync(join(dir, 'supabase', 'migrations'))) {
      const { preflight, emulatorChannel } = await import('./firebase/emulator.js');
      const { verifyFirebase } = await import('./firebase/verify.js');
      const pf = preflight();
      if (!pf.ok) { console.error('verified-changes (Firebase engine) needs its runtime:\n  - ' + pf.problems.join('\n  - ')); process.exit(2); }
      const channel = await emulatorChannel({ projectDir: dir });
      const r = await verifyFirebase({ projectDir: dir, channel });
      console.log(renderResult(r, { format: one('--format') === 'json' ? 'json' : 'text' }));
      process.exit(r.verdict === 'safe' ? 0 : r.verdict === 'untested' ? 2 : 1);
    }
    // A Prisma project (schema.prisma, no Supabase migrations) → the review-tier
    // Prisma advisor (Prisma authz is app-layer; the Postgres engine proves the SQL side).
    if (cmd === 'check' && !existsSync(join(dir, 'supabase', 'migrations'))) {
      const prismaPath = existsSync(join(dir, 'schema.prisma')) ? join(dir, 'schema.prisma')
        : existsSync(join(dir, 'prisma', 'schema.prisma')) ? join(dir, 'prisma', 'schema.prisma') : null;
      if (prismaPath) {
        const { prismaScan } = await import('../web/prisma-scan.js');
        const hasSqlMigrations = existsSync(join(dir, 'prisma', 'migrations')) || existsSync(join(dir, 'migrations'));
        const r = prismaScan(readFileSync(prismaPath, 'utf8'), { hasSqlMigrations });
        console.log(renderResult(r, { format: one('--format') === 'json' ? 'json' : 'text' }));
        process.exit(r.verdict === 'unsafe' ? 1 : 0);
      }
    }
    // Generic Postgres (non-Supabase) with GUC-based RLS: attack it as a non-owner
    // role. Detected only when it's clearly not a Supabase app (no supabase/migrations,
    // and the SQL uses current_setting for identity rather than auth.uid()).
    if (cmd === 'check' && !existsSync(join(dir, 'supabase', 'migrations'))) {
      const { gatherSql } = await import('./pgfiles.js');
      const sqls = gatherSql(dir);
      const joined = sqls.join('\n');
      if (sqls.length && /current_setting\s*\(/i.test(joined) && !/auth\.uid\s*\(/i.test(joined)) {
        const { verifyPostgres } = await import('./postgres.js');
        const r = await verifyPostgres({ migrations: sqls });
        console.log(renderResult(r, { format: one('--format') === 'json' ? 'json' : 'text' }));
        process.exit(r.verdict === 'safe' ? 0 : r.verdict === 'untested' ? 2 : 1);
      }
    }
    // The original milestone-1 layout (migration.sql + manifest.json) still works.
    if (isLegacyApp(dir)) {
      const app = loadApp(dir);
      const r = cmd === 'verify' ? await verify(app, readFileSync(change, 'utf8'), { logDir: one('--log') }) : await checkApp(app, { logDir: one('--log') });
      process.exit(emit(cmd === 'verify' ? 'verify' : 'check', { result: r, files: ['migration.sql'] }, dir));
    }
    if (cmd === 'verify' && !change && !one('--sql')) throw new ProjectError('verify needs the change: a migration path in the project, or --sql <file>');
    const run = await runCheck(dir, change);
    const code = emit(run.kind, run, dir);
    if (cmd !== 'guard') process.exit(code);
    if (code !== 0) { console.error('\nverified-changes: not running the command, the check did not pass.'); process.exit(1); }
    if (!tail.length) process.exit(0);
    const res = spawnSync(tail[0], tail.slice(1), { stdio: 'inherit', shell: process.platform === 'win32' });
    process.exit(res.status ?? 2);
  } else if (cmd === 'fix') {
    const dir = resolve(pos[0] || '.');
    const f = await writeFixMigration(dir, { public_tables: opts['--public'] || [], shared_tables: opts['--shared'] || [], includeUnproven: !!opts['--include-unproven'], log: !opts['--no-log'] });
    if (!f.written) { console.log(`verified-changes: ${f.before.verdict}; no proven database fixes to write${f.before.fixes?.length ? ' (the remaining fixes need a person: see the report from "check")' : ''}.`); process.exit(passed(f.before) ? 0 : 1); }
    console.log(`verified-changes: wrote ${f.written} with ${f.chosen.length} fix(es).`);
    console.log(`before: ${f.before.verdict} (Guard Score ${f.before.guardScore}); after: ${f.after.verdict} (Guard Score ${f.after.guardScore})`);
    const left = (f.after.fixes || []).filter(x => x.kind === 'code' || x.manual || x.proof?.status !== 'proven');
    if (left.length) console.log(`still needs a person: ${left.map(x => x.table).join(', ')}`);
    process.exit(passed(f.after) ? 0 : 1);
  } else if (cmd === 'map' || cmd === 'pgtap') {
    // Two views over a check: a permission map (who can do what per table) and
    // an exportable pgTAP regression suite. Both re-use the check just run.
    const dir = resolve(pos[0] || '.');
    const { mapToText, mapToJson, toPgtap } = await import('./matrix.js');
    const r = (await checkProject(dir, { log: false })).result;
    const format = one('--format') || (cmd === 'pgtap' ? 'sql' : 'text');
    const out = cmd === 'pgtap' ? toPgtap(r) : format === 'json' ? JSON.stringify(mapToJson(r), null, 2) : mapToText(r);
    const dest = one('--out');
    if (dest) { writeFileSync(dest, out + '\n'); console.log(`wrote ${dest}`); }
    else console.log(out);
  } else if (cmd === 'snapshot') {
    // Save the security state (RLS, policies, grants) so a later change can be
    // diffed against it — the "did this migration open something up?" check.
    const { captureState } = await import('./parity.js');
    const dir = resolve(pos[0] || '.');
    const { loadMigrations } = await import('./project.js');
    const state = await captureState(loadMigrations(dir).sql);
    const dest = one('--out') || join(dir, '.verified-changes', 'snapshot.json');
    mkdirSync(join(dest, '..'), { recursive: true });
    writeFileSync(dest, JSON.stringify(state, null, 1));
    console.log(`snapshot written to ${dest} (${Object.keys(state.tables).length} tables)`);
  } else if (cmd === 'diff') {
    // Compare the project now against a saved snapshot; report only the changes
    // that matter for security.
    const { captureState, diffState } = await import('./parity.js');
    const { loadMigrations } = await import('./project.js');
    const dir = resolve(pos[0] || '.');
    const snapPath = one('--snapshot') || join(dir, '.verified-changes', 'snapshot.json');
    if (!existsSync(snapPath)) throw new ProjectError(`no snapshot at ${snapPath}; run "verified-changes snapshot" first`);
    const before = JSON.parse(readFileSync(snapPath, 'utf8'));
    const after = await captureState(loadMigrations(dir).sql);
    const changes = diffState(before, after);
    if (one('--format') === 'json') { console.log(JSON.stringify(changes, null, 2)); }
    else if (!changes.length) console.log('No security-relevant changes since the snapshot.');
    else { console.log(`${changes.length} security-relevant change(s) since the snapshot:\n`); for (const c of changes) console.log(`  [${c.severity}] ${c.change}`); }
    process.exit(changes.some(c => c.severity === 'high') ? 1 : 0);
  } else if (cmd === 'secrets') {
    // Scan source/config for leaked secrets that ship to the client or a public
    // repo (service_role keys, Stripe/AWS/GCP/provider secrets, committed .env),
    // without flagging keys that are public by design (anon key, Firebase web config).
    const { scanSecrets } = await import('../web/secrets-scan.js');
    const { readdirSync, statSync } = await import('node:fs');
    const dir = resolve(pos[0] || '.');
    const SKIP = /(^|\/)(node_modules|\.git|dist|build|\.next|out|coverage|vendor)(\/|$)/;
    const EXT = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro|html|json|env|ya?ml|toml|sh|txt|md|py|rb|go)$/i;
    const files = [];
    (function walk(d) {
      for (const name of readdirSync(d)) {
        const p = join(d, name);
        if (SKIP.test(p)) continue;
        const s = statSync(p);
        if (s.isDirectory()) walk(p);
        else if ((EXT.test(name) || /(^|\/)\.env/.test(name)) && s.size < 2_000_000) { try { files.push({ path: p.replace(dir + '/', ''), content: readFileSync(p, 'utf8') }); } catch {} }
      }
    })(dir);
    const r = scanSecrets(files); r.filesScanned = files.length;
    console.log(renderResult(r, { format: one('--format') === 'json' ? 'json' : 'text' }));
    process.exit(r.verdict === 'unsafe' ? 1 : 0);
  } else if (cmd === 'watch') {
    // Continuous monitoring: re-check when the schema changes and report drift.
    const { watch } = await import('node:fs');
    const { driftReport } = await import('./monitor.js');
    const dir = resolve(pos[0] || '.');
    const runOnce = async () => (await checkProject(dir, { log: false })).result;
    let last = await runOnce();
    console.log(`watching ${dir} — Guard Score ${last.guardScore}/100 (${last.verdict}). Ctrl-C to stop.`);
    let timer = null;
    const target = existsSync(join(dir, 'supabase', 'migrations')) ? join(dir, 'supabase', 'migrations') : dir;
    watch(target, { recursive: true }, () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        try {
          const curr = await runOnce();
          const d = driftReport(last, curr);
          console.log(new Date().toISOString().slice(11, 19) + ' ' + d.headline);
          for (const f of d.introduced) console.log(`   + [new] ${f.class} on ${f.table}`);
          last = curr;
        } catch (e) { console.error('re-check failed:', e.message); }
      }, 400);
    });
    await new Promise(() => {}); // run until killed
  } else if (cmd === 'check-postgres') {
    // Explicit generic-Postgres RLS check (when auto-detection is too conservative).
    const { gatherSql } = await import('./pgfiles.js');
    const { verifyPostgres } = await import('./postgres.js');
    const dir = resolve(pos[0] || '.');
    const sqls = gatherSql(dir);
    if (!sqls.length) throw new ProjectError('no .sql migration/schema files found here');
    const r = await verifyPostgres({ migrations: sqls });
    console.log(renderResult(r, { format: one('--format') === 'json' ? 'json' : 'text' }));
    process.exit(r.verdict === 'safe' ? 0 : r.verdict === 'untested' ? 2 : 1);
  } else if (cmd === 'check-firebase') {
    // First-version Firebase support: a STATIC analysis of firestore.rules /
    // storage.rules (not the attack-proven model the Supabase check uses).
    const { checkFirebase } = await import('./firebase.js');
    const dir = resolve(pos[0] || '.');
    const r = checkFirebase(dir);
    if (!r) throw new ProjectError('no firestore.rules or storage.rules found here');
    if (one('--format') === 'json') { console.log(JSON.stringify(r, null, 2)); }
    else {
      console.log(`Firebase rules (static analysis of ${r.files} file(s) — read from the rules, not proven by attack):\n`);
      if (!r.findings.length) console.log('  No open or under-scoped rules found.');
      for (const f of r.findings) console.log(`  [${f.severity}] ${f.path}\n    ${f.rule}: ${f.detail}\n`);
    }
    process.exit(r.findings.some(f => f.severity === 'high') ? 1 : 0);
  } else if (cmd === 'scan-code') {
    // Static scan of the app's server code for what row-level security can't see:
    // unverified payment webhooks, client-set prices/roles, service-role routes
    // with no auth check.
    const { scanCode } = await import('./parity.js');
    const dir = resolve(pos[0] || '.');
    const findings = scanCode(dir);
    if (one('--format') === 'json') { console.log(JSON.stringify(findings, null, 2)); }
    else if (!findings.length) console.log('No server-code risks found (this scan is heuristic; it does not run the code).');
    else { console.log(`${findings.length} server-code warning(s) — outside row-level security, not proven by attack:\n`); for (const f of findings) console.log(`  [${f.severity}] ${f.file}\n    ${f.rule}: ${f.detail}\n`); }
    process.exit(findings.some(f => f.severity === 'high') ? 1 : 0);
  } else if (cmd === 'rules') {
    // Every attack the checker runs, in plain language. Answers "what does it
    // check for?" without running anything, like a linter's rule list.
    const { EXPLAIN } = await import('./fixes.js');
    if (one('--format') === 'json') console.log(JSON.stringify(Object.entries(EXPLAIN).map(([id, text]) => ({ id, text })), null, 2));
    else { console.log(`Verified Changes runs ${Object.keys(EXPLAIN).length} attack classes against a private copy, then confirms real users still work:\n`); for (const [id, text] of Object.entries(EXPLAIN)) console.log(`  ${id}\n    ${text}\n`); }
  } else if (cmd === 'badge') {
    // Emit a Guard Score badge (the viral loop). `badge <score>` renders that
    // score; `badge --md` prints the markdown snippet to paste into a README.
    const score = pos[0] != null && pos[0] !== '' ? Math.max(0, Math.min(100, Math.round(Number(pos[0])))) : null;
    if (pos[0] != null && pos[0] !== '' && !Number.isFinite(Number(pos[0]))) throw new ProjectError('badge needs a score 0-100, e.g. `verified-changes badge 59`');
    const out = opts['--md'] ? badgeMarkdown(score) : badgeSvg(score);
    if (one('--out')) { writeFileSync(one('--out'), out); console.log(`badge written to ${one('--out')}`); }
    else console.log(out);
  } else if (cmd === 'demo') {
    // Run the checker on a bundled deliberately-vulnerable app, so a new user
    // sees what a real finding looks like without a project of their own.
    const demo = new URL('../examples/demo-app', import.meta.url).pathname;
    if (!existsSync(demo)) throw new ProjectError('demo app not found in this install');
    console.log('Running a check on a bundled example app with three planted holes...\n');
    const run = await runCheck(demo, undefined);
    process.exit(emit(run.kind, run, demo));
  } else if (cmd === 'hook' && pos[0] === 'install') {
    const dir = resolve(pos[1] || '.');
    const hooks = join(dir, '.git', 'hooks');
    if (!existsSync(join(dir, '.git'))) throw new ProjectError(`not a git repository: ${dir}`);
    mkdirSync(hooks, { recursive: true });
    const f = join(hooks, 'pre-push');
    if (existsSync(f) && !readFileSync(f, 'utf8').includes('verified-changes')) throw new ProjectError(`${f} already exists; add "npx verified-changes check ." to it yourself`);
    writeFileSync(f, HOOK); chmodSync(f, 0o755);
    console.log(`installed ${f}: pushes that change supabase/migrations are checked first`);
  } else if (cmd === 'serve') {
    const { startServer } = await import('./server.js');
    await startServer({ port: Number(one('--port') || process.env.PORT || 8787) });
  } else if (cmd === 'audit' && pos[0]) {
    const a = auditLog(pos[0]);
    console.log(a.ok ? `${a.count} receipts: chain and signatures valid` : `INVALID: ${a.error}`);
    process.exit(a.ok ? 0 : 1);
  } else {
    console.log(readFileSync(new URL(import.meta.url), 'utf8').split('\n').filter(l => l.startsWith('//')).slice(1).map(l => l.slice(3)).join('\n'));
    process.exit(2);
  }
} catch (e) {
  console.error(`verified-changes: ${e instanceof ProjectError || e instanceof LiveError ? '' : 'error: '}${e.message}`);
  process.exit(2);
}
