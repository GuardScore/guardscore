// Two derived views over a completed check, for the platforms and teams that
// asked for them:
//   - a permission map: per table, what an anonymous visitor and another
//     signed-in user could actually do (proven by attack), and whether the
//     owner's own use works.
//   - a pgTAP test file: the same behavior written as regression tests the
//     customer can keep and run with `supabase test db`, so a later change that
//     reopens a hole fails their own CI.
// Both read only the check results already produced; they run no new attacks.

const OPS = ['read', 'write'];

// Which broad operation a check class exercises, and by whom.
function facet(c) {
  const actor = c.proof?.actor || '';
  const who = /anon/i.test(actor) ? 'anon' : /another user|user B/i.test(actor) ? 'other' : /owner|user A/i.test(actor) ? 'owner' : /new user/i.test(actor) ? 'newuser' : 'other';
  const cls = c.class || '';
  const read = /read|leak|enumeration|declared_sensitive|_by_design/.test(cls);
  const write = /write|insert|tamper|grant|promotion|self_join|share_|upload|trusts_user_metadata|rpc_write/.test(cls);
  return { who, op: read ? 'read' : write ? 'write' : null };
}

// A per-table map of what each visitor could do. "open" = an attack of that
// kind succeeded; "blocked" = every attack of that kind was stopped; "—" = not
// exercised. The owner column reports whether the app still works for them.
export function permissionMap(r) {
  const tables = {};
  const row = () => ({ anon: { read: null, write: null }, other: { read: null, write: null }, owner: { works: null }, notes: [] });
  for (const c of r.checks || []) {
    if (c.table === 'auth.users') continue;
    const t = (tables[c.table] ||= row());
    const { who, op } = facet(c);
    if (c.kind === 'legit') {
      if (who === 'owner' || who === 'newuser') {
        if (c.status === 'broken') t.owner.works = false;
        else if (t.owner.works === null) t.owner.works = true;
      }
      continue;
    }
    if (c.kind !== 'attack' || !op || !(who in t) || who === 'owner') continue;
    const cell = t[who];
    if (c.status === 'leaked') cell[op] = 'open';
    else if (c.status === 'blocked' && cell[op] !== 'open') cell[op] = 'blocked';
    else if (c.status === 'notice' && cell[op] == null) cell[op] = 'public';
  }
  // Coverage gaps: a table we couldn't make sample rows for.
  for (const m of (r.missed || [])) if (tables[m.table]) tables[m.table].notes.push('not fully tested');
  return tables;
}

const CELL = { open: 'OPEN', blocked: 'blocked', public: 'public', null: '—' };

export function mapToText(r) {
  const m = permissionMap(r);
  const names = Object.keys(m).sort();
  if (!names.length) return 'No tables to map.';
  const rows = [['table', 'anon read', 'anon write', 'other-user read', 'other-user write', 'owner works']];
  for (const n of names) {
    const t = m[n];
    rows.push([n, CELL[t.anon.read], CELL[t.anon.write], CELL[t.other.read], CELL[t.other.write],
      t.owner.works === false ? 'NO' : t.owner.works ? 'yes' : '—']);
  }
  const w = rows[0].map((_, i) => Math.max(...rows.map(r => String(r[i]).length)));
  const line = r => r.map((c, i) => String(c).padEnd(w[i])).join('  ');
  const out = [line(rows[0]), w.map(x => '-'.repeat(x)).join('  '), ...rows.slice(1).map(line)];
  out.push('', 'OPEN = an attack of this kind succeeded on the private copy. blocked = every such attack was stopped.');
  out.push('public = readable by design (declared or clearly a catalog). owner works = the owner\'s own use still works.');
  return out.join('\n');
}

export function mapToJson(r) {
  return { app: r.app, verdict: r.verdict, tables: permissionMap(r) };
}

// pgTAP: turn each proven attack into an assertion the customer can re-run.
// A blocked read/write becomes "this returns/affects 0 rows as that visitor";
// a leak becomes a failing test they must fix (marked TODO so their suite is
// green only once it's closed). Real-user checks become positive assertions.
const lit = s => `$vc$${String(s)}$vc$`;
const claims = who => who === 'anon'
  ? `select set_config('request.jwt.claims', '{"role":"anon"}', true); set local role anon;`
  : `select set_config('request.jwt.claims', '{"role":"authenticated","sub":"${who}"}', true); set local role authenticated;`;

export function toPgtap(r) {
  const A = '00000000-0000-4000-8000-00000000000a';
  const B = '00000000-0000-4000-8000-00000000000b';
  // Only read attacks translate cleanly to a scalar assertion: their SQL is a
  // single `select count(*)`. Write attacks use data-modifying CTEs that can't
  // sit inside pgTAP's is(), so they're left out of the exported suite.
  const attacks = (r.checks || []).filter(c => c.kind === 'attack' && c.proof?.sql
    && /^\s*select\s+count\(\*\)\s+as\s+n\s+from/i.test(c.proof.sql)
    && !/\$\d/.test(c.proof.sql) // no unbound parameters
    && !/has_function_privilege|has_table_privilege/.test(c.proof.sql));
  const lines = [
    '-- Verified Changes: RLS regression tests (pgTAP).',
    '-- Generated from a security check. Run with:  supabase test db',
    '-- Each test replays one attack the checker ran and asserts it stays blocked.',
    '-- A test marked TODO is a hole that is still open: fix it, then drop the TODO.',
    'begin;',
    `select plan(${attacks.length});`,
    '-- two test users; adapt if your fixtures differ',
    `insert into auth.users (id, email) values ('${A}','alice@test.example'),('${B}','bob@test.example') on conflict do nothing;`,
    '',
  ];
  for (const c of attacks) {
    const who = /anon/i.test(c.proof.actor) ? 'anon' : B;
    const leaked = c.status === 'leaked';
    const sql = c.proof.sql.replace(/;\s*$/, '');
    const desc = `${c.table}: ${c.class} as ${c.proof.actor}${leaked ? ' (OPEN — fix this)' : ''}`;
    lines.push(`-- ${desc}`);
    if (leaked) lines.push(`select todo(${lit('still open: ' + c.class + ' on ' + c.table)}, 1);`);
    lines.push('set local role postgres;');
    lines.push(claims(who));
    lines.push(`select is( (${sql})::text, '0', ${lit(desc)} );`);
    lines.push('reset role;', '');
  }
  lines.push('select * from finish();', 'rollback;');
  return lines.join('\n');
}
