// The client-side static scan behind the zero-install web front door. Two
// things must hold: it never screams "unsafe" at a safe DDL (precision, because
// trust is the product), and its wording stays in sync with the engine.
import { staticScan, EXPLAIN } from '../web/scan.js';
import { EXPLAIN as ENGINE } from '../src/fixes.js';

let fail = 0;
const ok = (cond, msg) => { if (!cond) { fail++; console.log('  FAIL', msg); } };

// --- catches the slam-dunk anon-facing holes ---
const noRls = staticScan(`create table public.profiles (id uuid primary key, user_id uuid, email text);`);
ok(noRls.verdict === 'unsafe' && noRls.findings.some(f => f.class === 'anon_write'), 'no-RLS table with PII → unsafe');

const allowAll = staticScan(`create table public.notes (id uuid, user_id uuid, body text);
  alter table public.notes enable row level security;
  create policy w on public.notes for all to anon using (true) with check (true);`);
ok(allowAll.verdict === 'unsafe' && allowAll.findings.some(f => f.class === 'anon_write'), 'allow-all-anon policy → unsafe');

const pubBucket = staticScan(`insert into storage.buckets (id, name, public) values ('documents','documents', true);`);
ok(pubBucket.findings.some(f => f.class === 'public_bucket'), 'public private-named bucket → flagged');

// --- does NOT false-alarm on safe patterns ---
const secure = staticScan(`create table public.notes (id uuid primary key, user_id uuid not null, body text);
  alter table public.notes enable row level security;
  create policy own on public.notes for all to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));`);
ok(secure.verdict === 'no_obvious_holes' && !secure.findings.length, 'owner-scoped table → clean');

// Supabase's default GRANT ALL TO anon must NOT be treated as a hole (RLS gates it).
const grantDefault = staticScan(`create table public.leads (id uuid, user_id uuid, email text);
  alter table public.leads enable row level security;
  create policy own on public.leads for select to authenticated using (user_id = auth.uid());
  grant all on public.leads to anon;`);
ok(grantDefault.verdict === 'no_obvious_holes', 'anon grant + owner RLS → clean (grant is the Supabase default)');

// Owner-scoped read with no `to` clause (defaults to PUBLIC) is still gated by the predicate.
const ownerPublicRole = staticScan(`create table public.prefs (id uuid primary key, user_id uuid);
  alter table public.prefs enable row level security;
  create policy p on public.prefs for select using (auth.uid() = user_id);`);
ok(ownerPublicRole.verdict === 'no_obvious_holes', 'owner-scoped select (public role) → clean');

// Non-public schema (stripe.*, *_private) is never anon-reachable, so never flagged.
const otherSchema = staticScan(`create table stripe.customers (id text, email text);
  create table komisio_private.secrets (id uuid, token text);`);
ok(otherSchema.verdict !== 'unsafe', 'non-public schema tables → not flagged');

// A plain anon-readable catalog (no sensitive columns) is a review-warning, not a red.
const catalog = staticScan(`create table public.products (id uuid primary key, name text, price numeric);
  alter table public.products enable row level security;
  create policy r on public.products for select using (true);`);
ok(catalog.verdict === 'review' && !catalog.findings.some(f => f.severity === 'critical'), 'anon-readable catalog → review, not critical');

// --- wording stays in sync with the engine ---
for (const k of ['anon_read', 'anon_write', 'public_bucket']) {
  ok(EXPLAIN[k] === ENGINE[k], `EXPLAIN.${k} matches the engine's wording`);
}

console.log(fail ? `web-scan: ${fail} check(s) failed` : 'web-scan checks passed (static front-door scanner)');
process.exit(fail ? 1 : 0);
