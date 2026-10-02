// Generic Postgres RLS attack engine: attacks a real PGlite copy as a non-owner
// role, so RLS actually applies. Safe (GUC-scoped) app passes; a using(true) app
// and a no-RLS table are proven unsafe with receipts.
import { verifyPostgres } from '../src/postgres.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

const SAFE = `
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy notes_owner on public.notes
  using (user_id = current_setting('app.user_id', true)::uuid)
  with check (user_id = current_setting('app.user_id', true)::uuid);
`;

const LEAK = `
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy notes_all on public.notes using (true) with check (true);
`;

const NORLS = `
create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  email text
);
`;

const safe = await verifyPostgres({ sql: SAFE });
ok(safe.stack === 'postgres', 'reports stack=postgres');
ok(safe.identityGuc === 'app.user_id', `detects the identity GUC (got ${safe.identityGuc})`);
ok(safe.verdict === 'safe' && safe.guardScore === 100, `GUC-scoped RLS → safe/100 (got ${safe.verdict}/${safe.guardScore})`);
ok(!safe.findings.length, 'no findings on a correctly-scoped app');

const leak = await verifyPostgres({ sql: LEAK });
ok(leak.verdict === 'unsafe' && leak.guardScore <= 59, `using(true) → unsafe, capped ≤59 (got ${leak.verdict}/${leak.guardScore})`);
ok(leak.findings.some(f => f.class === 'cross_user_read' || f.class === 'anon_read'), 'proves a cross-user / anon read');
ok(leak.findings.some(f => f.class === 'cross_user_write'), 'proves a cross-user write (delete of another user’s rows)');
ok(leak.findings.every(f => f.proof && f.proof.actor && f.proof.observed && f.fix), 'every finding carries a proof receipt and a fix');

const norls = await verifyPostgres({ sql: NORLS });
ok(norls.verdict === 'unsafe' && norls.findings.some(f => f.class === 'no_rls'), 'RLS-off table with an owner column → unsafe (no_rls)');

console.log(fail ? `postgres-engine: ${fail} failed` : 'postgres-engine checks passed (generic Postgres RLS attack engine)');
process.exit(fail ? 1 : 0);
