// Live mode: check what's actually deployed, not just the migration files.
//
// Vibecoders change their database in the Supabase dashboard, and builders
// change it directly, so supabase/migrations drifts from the real project. Live
// mode reads the real project's schema (structure, policies, functions, grants:
// never rows), builds the private copy from that, attacks it as usual, and
// reports every difference from the migrations.
//
// Where the schema comes from, in order of preference:
//   --live-dump <file>   a schema dump you already have (CI, a platform export)
//   --live <db-url>      pg_dump --schema-only against that connection string
//   --linked             `supabase db dump` for the project the Supabase CLI is linked to
// All three read structure only. The URL never leaves this machine.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildDb } from './db.js';

export class LiveError extends Error {}

export function pullSchema({ dump, dbUrl, linked, cwd = process.cwd() }) {
  if (dump) {
    if (!existsSync(dump)) throw new LiveError(`schema dump not found: ${dump}`);
    return readFileSync(dump, 'utf8');
  }
  const dir = mkdtempSync(join(tmpdir(), 'vc-live-'));
  const out = join(dir, 'schema.sql');
  try {
    const run = dbUrl
      ? spawnSync('pg_dump', ['--schema-only', '--no-owner', '--schema=public', '--file', out, dbUrl], { encoding: 'utf8' })
      : linked
        ? spawnSync('supabase', ['db', 'dump', '--schema', 'public', '--file', out], { encoding: 'utf8', cwd })
        : null;
    if (!run) throw new LiveError('give --live-dump <file>, --live <db-url> or --linked');
    if (run.error?.code === 'ENOENT') throw new LiveError(`${dbUrl ? 'pg_dump' : 'the Supabase CLI'} is not installed or not on PATH`);
    if (run.status !== 0) throw new LiveError(`could not read the live schema: ${(run.stderr || '').trim().split('\n').slice(-3).join(' ')}`);
    return readFileSync(out, 'utf8');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Make a pg_dump of a Supabase project load into the local copy: drop psql
// meta-commands and session settings the copy doesn't want, and grants to
// Supabase-internal roles the copy doesn't have.
const KNOWN_ROLES = /\b(anon|authenticated|service_role|postgres|public)\b/i;
export function sanitizeDump(sql) {
  return sql.split('\n').filter(line => {
    if (/^\\/.test(line)) return false;                                   // \restrict, \connect
    if (/^SELECT pg_catalog\.set_config\('search_path', ''/.test(line)) return false;
    if (/^SET (row_security|default_table_access_method|transaction_timeout|idle_in_transaction_session_timeout|lock_timeout|statement_timeout)/i.test(line)) return false;
    if (/^(GRANT|REVOKE)\b/i.test(line)) {
      const to = line.match(/\b(?:TO|FROM)\s+(.+?);?$/i)?.[1] || '';
      return to.split(',').every(r => KNOWN_ROLES.test(r.trim().replace(/"/g, '')));
    }
    if (/^ALTER DEFAULT PRIVILEGES/i.test(line)) return false;
    if (/^COMMENT ON SCHEMA public/i.test(line)) return false;
    return true;
  }).join('\n')
    .replace(/^CREATE SCHEMA public;$/m, 'CREATE SCHEMA IF NOT EXISTS public;')
    .replace(/^CREATE PUBLICATION[^;]*;$/gm, '');
}

// Structure that decides who can do what, as comparable text.
async function accessShape(db) {
  const q = async s => (await db.query(s)).rows;
  const shape = new Map();
  for (const r of await q(`select c.relname as t, c.relrowsecurity as rls, c.relkind as k from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind in ('r','v','m') and c.relname !~ '^vc_'`)) {
    shape.set(`${r.k === 'r' ? 'table' : 'view'} ${r.t}`, r.k === 'r' ? `row level security ${r.rls ? 'on' : 'off'}` : 'exists');
  }
  for (const r of await q(`select tablename as t, policyname as p, cmd, roles::text as roles, coalesce(qual, '') as u, coalesce(with_check, '') as c from pg_policies where schemaname = 'public'`)) {
    shape.set(`policy "${r.p}" on ${r.t}`, `${r.cmd} to ${r.roles} using (${r.u}) with check (${r.c})`);
  }
  for (const r of await q(`select p.oid::regprocedure::text as sig, p.prosecdef as def, md5(p.prosrc) as h from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname !~ '^vc_' and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`)) {
    shape.set(`function ${r.sig}`, `${r.def ? 'security definer' : 'security invoker'}, body ${r.h.slice(0, 8)}`);
  }
  for (const r of await q(`select c.relname as t, coalesce(array_to_string(c.reloptions, ','), '') as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'v'`)) {
    shape.set(`view ${r.t}`, r.o.includes('security_invoker=true') ? 'exists, security_invoker' : 'exists, owner rights');
  }
  return shape;
}

/** Differences between what the migrations build and what's deployed. */
export async function drift(migrationSql, liveSql) {
  const a = await buildDb({ migrations: [migrationSql], seed: '', fresh: true });
  const b = await buildDb({ migrations: [liveSql], seed: '', fresh: true });
  try {
    const [sa, sb] = [await accessShape(a), await accessShape(b)];
    const out = [];
    for (const [k, v] of sb) {
      if (!sa.has(k)) out.push({ kind: 'only_live', item: k, live: v, detail: `${k} exists in the live database but not in your migrations (${v})` });
      else if (sa.get(k) !== v) out.push({ kind: 'changed', item: k, live: v, migrations: sa.get(k), detail: `${k} differs: live is "${v}", migrations say "${sa.get(k)}"` });
    }
    for (const [k, v] of sa) if (!sb.has(k)) out.push({ kind: 'only_migrations', item: k, migrations: v, detail: `${k} is in your migrations but not in the live database` });
    return out.sort((x, y) => x.item.localeCompare(y.item));
  } finally {
    await a.close(); await b.close();
  }
}
