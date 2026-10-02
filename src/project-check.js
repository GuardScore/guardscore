// One entry point for every way a platform calls the verifier: the MCP server
// (an agent calls it), the command line and migration guard (a developer or a
// deploy script calls it), the GitHub Action (CI calls it), and the HTTP API (a
// builder platform calls it). They all check a Supabase project folder: the
// migrations in supabase/migrations plus the app's own files for leaked keys.
import { resolve, join, relative, dirname } from 'node:path';
import { existsSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { checkApp, verify } from './verify.js';
import { loadMigrations, buildManifest } from './project.js';
import { pullSchema, sanitizeDump, drift } from './live.js';
import { buildDb } from './db.js';

export class ProjectError extends Error {}

export function loadProject(dir, { public_tables = [], shared_tables = [] } = {}, excludeFile = null) {
  const root = resolve(dir);
  if (!existsSync(root)) throw new ProjectError(`project folder not found: ${root}`);
  const manifest = buildManifest(root, { public_tables, shared_tables });
  const { sql, files, layout } = loadMigrations(root, excludeFile ? resolve(root, excludeFile) : null);
  return { dir: root, manifest, sql, files, layout };
}

/**
 * Check a project as it stands, or a change to it.
 *   change_file  a migration in the project that is the change (everything before it is the app)
 *   change_sql   a change not yet written to a file
 *   log          write a signed receipt to <project>/.verified-changes (default true)
 */
export async function checkProject(dir, opts = {}) {
  const { change_file, change_sql, log = true, live } = opts;
  if (change_file && change_sql) throw new ProjectError('give change_file or change_sql, not both');
  const p = loadProject(dir, opts, change_file);
  // Live mode: build the copy from what's deployed, and list how it differs
  // from the migrations.
  let liveSql = null, driftList = null;
  if (live) {
    liveSql = sanitizeDump(pullSchema({ ...live, cwd: p.dir }));
    if (p.files.length) driftList = await drift(p.sql, liveSql);
  }
  if (!p.files.length && !liveSql && !change_sql && !change_file) throw new ProjectError('no migrations found: put the SQL in supabase/migrations/*.sql');
  const app = { name: 'project', sourceDir: p.dir, manifest: p.manifest, migration: liveSql ?? p.sql, seed: '' };
  const logDir = log ? join(p.dir, '.verified-changes') : undefined;
  if (change_file || change_sql) {
    const change = change_sql ?? readFileSync(resolve(p.dir, change_file), 'utf8');
    const result = await verify(app, change, { logDir });
    if (liveSql) Object.assign(result, { source: 'live', drift: driftList });
    return { kind: 'verify', files: p.files, result };
  }
  const result = await checkApp(app, { logDir, only: opts.only });
  if (liveSql) Object.assign(result, { source: 'live', drift: driftList });
  return { kind: 'check', files: p.files, result };
}

// A project sent as file contents (the HTTP API): written to a private temp
// folder, checked, and deleted. Only migrations, app source and the declaration
// file are accepted; paths can't escape the folder.
const ALLOWED = /^(supabase\/migrations\/[^/]+\.sql|verified-changes\.json|\.env[^/]*|(src|app|pages|components|lib|public|api|server|functions|supabase\/functions)\/.+\.(m?[jt]sx?|cjs|vue|svelte|astro|html?|json))$/;
export async function checkFiles(files, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'vc-'));
  try {
    for (const [path, content] of Object.entries(files || {})) {
      const clean = String(path).replace(/^\.?\/+/, '');
      if (clean.includes('..') || !ALLOWED.test(clean)) throw new ProjectError(`file not accepted: ${path} (send supabase/migrations/*.sql, verified-changes.json and app source files)`);
      if (typeof content !== 'string') throw new ProjectError(`file ${path}: content must be a string`);
      mkdirSync(dirname(join(dir, clean)), { recursive: true });
      writeFileSync(join(dir, clean), content);
    }
    return await checkProject(dir, { ...opts, log: false });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export const passed = r => r.verdict === 'safe';

// Proven fixes, written as the next migration. Only fixes that were applied to
// the private copy and re-checked go in, unless includeUnproven is set; the
// project is checked again with the new file in place before this returns.
export async function writeFixMigration(dir, opts = {}) {
  const before = await checkProject(dir, { ...opts, log: false });
  const r = before.result;
  const chosen = (r.fixes || []).filter(f => f.kind !== 'code' && !f.manual && (f.proof?.status === 'proven' || opts.includeUnproven));
  if (!chosen.length) return { written: null, before: r, after: r, chosen };
  // The fix has to run after every migration it depends on, so its name must
  // sort after the last existing one, even if an agent numbered those ahead of
  // the clock (20260925022000 while it's 02:01).
  const now = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const last = loadMigrations(resolve(dir)).files.map(f => (f.split('/').pop().match(/^(\d{14})/) || [])[1]).filter(Boolean).sort().pop();
  const stamp = last && last >= now ? String(BigInt(last) + 1n) : now;
  const rel = `supabase/migrations/${stamp}_verified_changes_fix.sql`;
  const body = [
    `-- Fixes from Verified Changes (${new Date().toISOString().slice(0, 10)}).`,
    `-- Each block was applied to a private copy of this database and re-checked: the attacks it`,
    `-- targets are blocked and the app's real users can still do what they did before.`,
    ...chosen.flatMap(f => ['', `-- ${f.table}: ${f.problems.join(' ')}`, `-- ${f.proof?.status === 'proven' ? 'PROVEN' : 'NOT PROVEN (review before deploying)'}: ${f.proof?.note || ''}`, f.sql]),
    '',
  ].join('\n');
  mkdirSync(join(resolve(dir), 'supabase', 'migrations'), { recursive: true });
  writeFileSync(join(resolve(dir), rel), body);
  const after = await checkProject(dir, { ...opts, log: opts.log ?? true });
  return { written: rel, before: r, after: after.result, chosen };
}

// When the migrations fail, say which file: apply them one at a time on a
// fresh copy until one fails. Agents fix the right file far more often when
// told which one it is.
export async function explainMigrationFailure(dir, error) {
  const root = resolve(dir);
  const { files } = loadMigrations(root);
  const done = [];
  for (const f of files) {
    const sql = readFileSync(join(root, f), 'utf8');
    try {
      const db = await buildDb({ migrations: [...done, sql], seed: '', fresh: true });
      await db.close();
      done.push(sql);
    } catch (e) {
      return `${f} fails: ${e.message}${done.length ? ` (the ${done.length} migration(s) before it apply fine)` : ''}`;
    }
  }
  return error?.message || String(error);
}
