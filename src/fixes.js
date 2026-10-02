// Turns findings into fixes a vibecoder can use: a prompt to paste into their
// builder, plus the SQL the builder should end up producing. The verifier
// re-checks after the fix, so the SQL is a reference, not something we trust blindly.
const q = n => `"${n.replace(/"/g, '""')}"`;

// Postgres combines permissive policies with OR, so a correct policy added next
// to a `using (true)` policy changes nothing. Every fix drops what's there first.
function dropAll(schema, table) {
  const lit = s => `'${s.replace(/'/g, "''")}'`;
  return `do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = ${lit(schema)} and tablename = ${lit(table)} loop
    execute format('drop policy %I on %I.%I', p.policyname, ${lit(schema)}, ${lit(table)});
  end loop;
end $$;`;
}

// Infinite recursion: a policy on L reads L, which applies L's policies again.
// The fix keeps every policy's meaning and only changes how L is read inside
// them: through private.<L>_rows(), a security-definer function (it runs as the
// table owner, so no policies re-apply) in a schema the Supabase API does not
// expose, so nobody can call it directly. Each self-referencing policy is
// recreated with the same command, roles and mode, with "from L" and "join L"
// pointed at the function (keeping the alias, or using L as the alias).
// Mutual recursion (L's policy reads M, M's reads L) is broken the same way:
// L's policies read M through private.<M>_rows().
function recursionFix(L) {
  const lit = v => `'${String(v).replace(/'/g, "''")}'`;
  // Patterns are built inside Postgres per target table X (%s = X, regex-escaped).
  const ref = String.raw`(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)`;
  const bare = String.raw`(from|join)\s+(public\.)?"?%s"?(?=\s+(where|join|left|right|inner|full|cross|on|group|order|limit|offset|union|except|intersect)\M|\s*\)|\s*$)`;
  const aliased = String.raw`(from|join)\s+(public\.)?"?%s"?(?=\s+[a-z_"])`;
  return [
    `create schema if not exists private;`,
    `grant usage on schema private to anon, authenticated;`,
    `do $fix$ declare x text; p record; u text; c text; r text; e text;`,
    `begin`,
    `  -- the tables whose lookups loop back into ${L}: ${L} itself, and any table whose policies read ${L}`,
    `  for x in select ${lit(L)} union select distinct tablename from pg_policies where schemaname = 'public' and tablename <> ${lit(L)}`,
    `      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format(${lit(ref)}, ${lit(L.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))}) loop`,
    `    e := regexp_replace(x, '([.*+?^\${}()|\\[\\]\\\\])', '\\\\\\1', 'g');`,
    `    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = ${lit(L)}`,
    `      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format(${lit(ref)}, e)) then continue; end if;`,
    `    execute format('create or replace function private.%I() returns setof public.%I language sql stable security definer set search_path = pg_catalog, public as $f$ select * from public.%I $f$', x || '_rows', x, x);`,
    `    execute format('revoke all on function private.%I() from public', x || '_rows');`,
    `    execute format('grant execute on function private.%I() to anon, authenticated', x || '_rows');`,
    `    for p in select * from pg_policies where schemaname = 'public' and tablename = ${lit(L)}`,
    `      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format(${lit(ref)}, e) loop`,
    `      u := p.qual; c := p.with_check;`,
    `      -- no alias: keep the table name as the alias so column references still resolve`,
    `      u := regexp_replace(u, format(${lit(bare)}, e), format('\\1 private.%I() %I', x || '_rows', x), 'gi');`,
    `      c := regexp_replace(c, format(${lit(bare)}, e), format('\\1 private.%I() %I', x || '_rows', x), 'gi');`,
    `      u := regexp_replace(u, format(${lit(aliased)}, e), format('\\1 private.%I()', x || '_rows'), 'gi');`,
    `      c := regexp_replace(c, format(${lit(aliased)}, e), format('\\1 private.%I()', x || '_rows'), 'gi');`,
    `      select string_agg(quote_ident(y), ', ') into r from unnest(p.roles) y;`,
    `      execute format('drop policy %I on public.%I', p.policyname, p.tablename);`,
    `      execute format('create policy %I on public.%I as %s for %s to %s', p.policyname, p.tablename, p.permissive, p.cmd, r)`,
    `        || coalesce(' using (' || u || ')', '') || coalesce(' with check (' || c || ')', '');`,
    `    end loop;`,
    `  end loop;`,
    `end $fix$;`,
  ].join('\n');
}

// A team's creator becomes its first member: added by a trigger on the team
// table, named to run after the app's own triggers, and only if they aren't
// a member yet.
function creatorTrigger(t) {
  const fk = (t.fks || []).find(f => f.col === t.tenant && f.refSchema === 'public');
  if (!fk) return [];
  const fn = q(`zz_vc_add_creator_to_${t.name}`);
  const roleCol = t.memberRole ? `, ${q(t.memberRole.col)}` : '';
  // The top role the table allows (owner before admin) for whoever created the group.
  const roleVal = t.memberRole ? `, '${String(t.memberRole.top || t.memberRole.admin).replace(/'/g, "''")}'` : '';
  return [`create or replace function public.${fn}() returns trigger language plpgsql security definer set search_path = public as $trg$`,
    `begin`,
    `  if auth.uid() is not null and not exists (select 1 from public.${q(t.name)} where ${q(t.owner)} = auth.uid() and ${q(t.tenant)} = new.${q(fk.refCol)}) then`,
    `    insert into public.${q(t.name)} (${q(t.owner)}, ${q(t.tenant)}${roleCol}) values (auth.uid(), new.${q(fk.refCol)}${roleVal});`,
    `  end if;`, `  return new;`, `end $trg$;`,
    `drop trigger if exists ${fn} on public.${q(fk.refTable)};`,
    `create trigger ${fn} after insert on public.${q(fk.refTable)} for each row execute function public.${fn}();`];
}

// The table's own access rule, from the key the checker found.
function keyPolicies(t, membership) {
  if (t.owner && !t.tenant) return ownerPolicies(t);
  if (t.tenant) return tenantPolicies(t, membership);
  if (t.keyKind === 'parent') return parentPolicies(t);
  return null;
}

// A user may only put their own sign-in email in an email column.
const emailGuard = t => {
  const c = (t.columns || []).find(c => /^(email|email_address|contact_email)$/i.test(c));
  return c ? ` and (${q(c)} is null or ${q(c)} = auth.jwt() ->> 'email')` : '';
};

function ownerPolicies(t) {
  const T = `public.${q(t.name)}`;
  const own = `${q(t.owner)} = auth.uid()`;
  // One row per user, made at signup: users don't insert it themselves.
  const insertable = !(t.oneRowPerUser && !(t.legitOps || []).includes('insert'));
  return [
    `alter table ${T} enable row level security;`,
    dropAll('public', t.name),
    `create policy ${q(`${t.name}_select_own`)} on ${T} for select to authenticated using (${own});`,
    ...(insertable ? [`create policy ${q(`${t.name}_insert_own`)} on ${T} for insert to authenticated with check (${own}${emailGuard(t)});`] : []),
    `create policy ${q(`${t.name}_update_own`)} on ${T} for update to authenticated using (${own}) with check (${own});`,
    `create policy ${q(`${t.name}_delete_own`)} on ${T} for delete to authenticated using (${own});`,
  ];
}

function tenantPolicies(t, m) {
  const T = `public.${q(t.name)}`;
  // The link found when the schema was read (a membership table, or the
  // user's own account row) comes first; else the schema's membership table.
  const via = t.tenantVia && t.tenantVia.table !== t.name ? t.tenantVia : null;
  const inTenant = via
    ? `${q(t.tenant)} in (select ${q(via.groupCol)} from public.${q(via.table)} where ${q(via.userCol)} = auth.uid())`
    : m && m.owner && m.tenant
    ? `${q(t.tenant)} in (select ${q(m.tenant)} from public.${q(m.name)} where ${q(m.owner)} = auth.uid())`
    : `/* replace with your membership lookup */ false`;
  return [
    `alter table ${T} enable row level security;`,
    dropAll('public', t.name),
    `create policy ${q(`${t.name}_tenant_members`)} on ${T} for all to authenticated using (${inTenant}) with check (${inTenant});`,
    // Whoever creates a row (a new team, say) isn't a member of it yet: let them
    // insert rows that name them as the creator.
    ...(t.owner && t.owner !== t.tenant ? [`create policy ${q(`${t.name}_insert_own`)} on ${T} for insert to authenticated with check (${q(t.owner)} = auth.uid());`]
      // The group table itself with no creator column: the app lets signed-in
      // users create groups, and a new empty group exposes nothing.
      : (t.tenantVia?.group === t.name || (t.generated || []).includes(t.tenant)) && (t.legitOps || []).includes('insert') ? [`create policy ${q(`${t.name}_insert_signed_in`)} on ${T} for insert to authenticated with check (true);`] : []),
  ];
}

// A row can be reached if its parent row can: the subquery runs under the
// caller's own policies on the parent table.
function parentPolicies(t) {
  const T = `public.${q(t.name)}`;
  const f = t.fks.find(x => x.col === t.key);
  const viaParent = `exists (select 1 from public.${q(f.refTable)} p where p.${q(f.refCol)} = ${T}.${q(t.key)})`;
  return [
    `alter table ${T} enable row level security;`,
    dropAll('public', t.name),
    `create policy ${q(`${t.name}_via_${f.refTable}`)} on ${T} for all to authenticated using (${viaParent}) with check (${viaParent});`,
  ];
}

// Role changes only from the server: users can't set their own role column.
// A new row a user creates always gets the least-privileged value.
function roleLock(t) {
  const fn = q(`vc_lock_${t.name}_${t.role.col}`);
  const c = q(t.role.col);
  const low = `'${String(t.role.low).replace(/'/g, "''")}'`;
  return [
    `create or replace function public.${fn}() returns trigger language plpgsql as $lock$
begin
  -- pg_trigger_depth() = 1: the client's own statement; the app's triggers (recomputing a total) still work
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new.${c} := ${low};
    elsif new.${c} is distinct from old.${c} then
      raise exception 'permission denied: only the server can change ${t.role.col.replace(/'/g, "''")}';
    end if;
  end if;
  return new;
end $lock$;`,
    `drop trigger if exists ${fn} on public.${q(t.name)};`,
    `create trigger ${fn} before insert or update on public.${q(t.name)} for each row execute function public.${fn}();`,
  ];
}

export const EXPLAIN = {
  anon_read: 'Anyone on the internet, without logging in, can read this table.',
  anon_write: 'Anyone on the internet, without logging in, can change or delete rows in this table.',
  cross_user_read: 'Any logged-in user can read other users\' rows.',
  cross_tenant_read: 'Users in one organization can read another organization\'s data.',
  cross_user_write: 'Any logged-in user can change or delete other users\' rows.',
  impersonated_insert: 'A user can create rows that claim to belong to someone else.',
  tenant_self_join: 'A user can add themselves to another organization.',
  trusts_user_metadata: 'Access depends on user_metadata, which users can edit themselves, so anyone can grant themselves access.',
  storage_read: 'Other people can see this user\'s uploaded files.',
  storage_write: 'Other people can delete this user\'s uploaded files.',
  storage_upload: 'People who shouldn\'t can upload files here: anonymous visitors to any path, or a user into another user\'s folder. Anyone can host content under your domain or overwrite what others expect to find there.',
  public_secret: 'This table is treated as public, but it holds secrets (share tokens, password hashes or keys), so anyone can read all of them: for share links, that means every shared item, not just the ones they were given.',
  view_bypass: 'A view shows data from private tables to people who can\'t read those tables: views run with their owner\'s rights and skip row level security unless created with security_invoker.',
  declared_sensitive: 'This table is declared readable by everyone (or every signed-in user), but it holds personal data such as emails or phone numbers of other users, which the declaration doesn\'t cover.',
  rpc_leak: 'A database function that runs with its owner\'s rights (security definer) returns other users\' private data to whoever calls it.',
  definer_exposed: 'A function that changes data with its owner\'s rights was meant for the server only (the migration revokes it from PUBLIC or grants it to service_role), but anonymous visitors or any signed-in user can still run it: Supabase grants anon and authenticated their own EXECUTE, which revoking from PUBLIC doesn\'t remove.',
  token_enumeration: 'Anyone can list shared items or their share tokens without having a link, so every "secret" link is effectively public.',
  privileged_tamper: 'A user can set money, status or counter fields on their own rows (mark their own order paid or delivered, set a price to 0, add credits, give their own review 99999 helpful votes or a verified badge) that only staff or the server should set.',
  team_self_promotion: 'A member can promote themselves to a higher role in their team (for example member to owner).',
  self_grant_admin: 'Any user can make themselves an admin by setting their own role, and your access rules trust that role.',
  privilege_escalation: 'A user granted limited access (a shared collaborator) can escalate it — for example reassign a shared item to themselves — because the write rule checks their access but not the fields only the owner should change.',
  rpc_write: 'A database function that runs with its owner\'s rights (security definer) changes other users\' data for whoever calls it.',
  secret_bypass: 'A lookup by secret (a share token, an invite code) returns data for a wrong secret, so anyone can open shared items without the link.',
  negative_value: 'A user can set a quantity or amount on their own order to a negative number, which turns a purchase into a refund or credit.',
  foreign_parent_write: 'A user can attach their own rows to someone else\'s private item (log a check-in on another user\'s habit, add a project under another user\'s client), which shows up in or blocks the other user\'s data.',
  public_bucket: 'A storage bucket whose name says it holds private files is public: anyone with a file\'s URL can download it, whatever the storage policies say.',
  shared_data_write: 'Any signed-in user can change or delete rows that belong to nobody in particular (a product catalog, settings), for example set every price to 0.',
  share_foreign_item: 'A user can create a share link for someone else\'s private item and then open it with their own link.',
  service_key_exposed: 'The service-role key is shipped to the browser. It skips every row level security rule, so anyone who opens the app can read, change or delete all data in the database.',
};

export function makeRecursionFix(loopTable, hits = []) {
  const rule2 = `policies on "${loopTable}" read the tables they loop through (including "${loopTable}" itself) through security-definer functions in a schema the API doesn't expose, so a lookup doesn't re-apply the same policies; what each role may do stays exactly the same`;
  return { table: loopTable, loopTable, problems: [`A policy on "${loopTable}" reads "${loopTable}" again (directly or through another table's policy), so every query that touches it fails with "infinite recursion" and the app errors for everyone.`],
    prompt: [`Fix the row level security on "${loopTable}" in my Supabase database.`, `Problem: a policy on "${loopTable}" reads "${loopTable}" again, so Postgres stops every query with "infinite recursion" and the app errors for everyone.`, `Rule to enforce: ${rule2}.`, `Don't change what each role is allowed to do.`].join('\n'),
    sql: recursionFix(loopTable), findings: hits };
}

// What a real user runs into, from the legit checks that failed.
function legitProblem(items) {
  const legit = items.filter(i => i.class === 'legit');
  if (legit.some(i => i.id.endsWith('.legit.new_user_row'))) return 'A new user can never get a row here: there is no signup trigger that creates it and no policy that lets them create it, so everything that needs it fails for every new user.';
  const noted = legit.find(i => i.proof?.note && i.id.endsWith('.legit.create'));
  if (noted) return `Creating a row here fails for every user: ${noted.proof.note.replace(/^creating a row in "[^"]+" runs/, 'it runs').replace(/, so it fails for every user$/, '')}. Change the trigger to use a value the rule allows, or widen the rule.`;
  const err = legit.map(i => i.proof?.observed?.error).find(e => e && !/infinite recursion/i.test(e));
  if (err && /permission denied for table users/i.test(err)) return 'Every query on this table fails with "permission denied for table users": a policy reads auth.users, which signed-in users cannot read.';
  if (err && !/row-level security/i.test(err)) return legit.some(i => /\.legit\.call\b/.test(i.id)) ? `Calling this function fails for real users with "${err}", so the feature that uses it errors.` : `Queries on this table fail for real users with "${err}", so the app errors.`;
  return 'The owner can no longer use their own data: the rules are so strict they block legitimate use.';
}

export function buildFixes(schema, results) {
  const bad = results.filter(r => r.status === 'leaked' || r.status === 'broken');
  const byTable = new Map();
  for (const r of bad) {
    if (!byTable.has(r.table)) byTable.set(r.table, []);
    byTable.get(r.table).push(r);
  }
  const membership = schema.find(t => t.membership);
  const fixes = [];
  for (let [table, items] of byTable) {
    const t = schema.find(s => s.name === table);
    // Problems with a self-contained fix get it on their own, so a table with
    // several kinds of problem gets several small fixes instead of one rewrite.
    const addons = [
      [i => i.class === 'foreign_parent_write', 'foreign_parent_write'],
      [i => /\.legit\.per_user_unique\./.test(i.id), 'per_user_unique'],
      [i => i.id.endsWith('.legit.create_and_read_back'), 'read_back'],
      [i => i.class === 'negative_value', 'negative_value'],
      [i => /\.invitee\.raise_role\./.test(i.id), 'invite_role'],
      [i => /\.legit\.staff_update\./.test(i.id), 'staff_update'],
    ];
    for (const [pick] of addons) {
      const part = items.filter(pick);
      if (!part.length || part.length === items.length) continue;
      const sub = buildFixes(schema, part);
      if (!sub.length || sub.some(f => /alter table public\.[^ ]+ enable row level security;\s*$/.test(f.sql) && !f.findings.length)) continue;
      for (const f of sub) f.findings = [...new Set(f.findings)];
      fixes.push(...sub.filter(f => !fixes.some(g => g.table === f.table && g.sql === f.sql)));
      items = items.filter(i => !pick(i));
    }
    const classes = [...new Set(items.map(i => i.class))];
    const recursion = items.find(i => /infinite recursion detected in policy for relation "([^"]+)"/i.test(i.proof?.observed?.error || ''));
    const loopTable = recursion?.proof.observed.error.match(/relation "([^"]+)"/i)[1];
    const problems = classes.map(c => c === 'legit'
      ? (recursion
        ? `Every query on this table fails with "infinite recursion": a policy on "${loopTable}" reads "${loopTable}" itself, so the app errors for everyone.`
        : legitProblem(items))
      : EXPLAIN[c]).filter(Boolean);

    let sql = [];
    let rule;
    const legitIds = items.filter(i => i.class === 'legit').map(i => i.id);
    // A helper function that errors ("column reference user_id is ambiguous"):
    // a PL/pgSQL parameter named like a column. Telling PL/pgSQL to prefer the
    // parameter keeps what the author meant (table.col = the argument).
    const ambiguous = items.map(i => (i.proof?.observed?.error || '').match(/column reference "([^"]+)" is ambiguous/i)).find(Boolean);
    if (ambiguous) {
      const col = ambiguous[1].replace(/'/g, "''");
      // Only the functions that actually failed (named by their own checks),
      // or else the helpers this table's policies call; never a function with
      // ON CONFLICT (col), where the pragma would change which column it means.
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      const failing = [...new Set(items.filter(i => /is ambiguous/i.test(i.proof?.observed?.error || '') && /\.legit\.call$/.test(i.id)).map(i => i.id.replace(/\.legit\.call$/, '')))];
      const helpers = (t?.policies || []).flatMap(p => [...p.text.matchAll(/\b([a-z_][a-z0-9_]*)\s*\(/gi)].map(m => m[1])).filter(n => !/^(auth|exists|coalesce|any|lower|upper|now|select)$/i.test(n));
      const names = failing.length ? failing : [...new Set(helpers)];
      const nameFilter = names.length ? ` and p.proname in (${names.map(lit).join(', ')})` : '';
      if (!fixes.some(f => f.ambiguousCol === col)) {
        const prob = `A database function used by the access rules fails with "column reference ${col} is ambiguous": its parameter has the same name as a column, so every query that runs it errors.`;
        fixes.push({ table, ambiguousCol: col, problems: [prob],
          prompt: [`Fix the functions in my Supabase database that have a parameter named "${col}".`, `Problem: ${prob}`, `Rule to enforce: inside those functions, "${col}" means the parameter; rename the parameter (for example p_${col}) or qualify the column with its table. Don't change what the function checks.`].join('\n'),
          sql: [`do $fix$ declare f record; d text; begin`,
            `  for f in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang`,
            `    where n.nspname = 'public' and l.lanname = 'plpgsql' and '${col}' = any(p.proargnames) and p.prosrc !~* 'variable_conflict' and p.prosrc !~* 'on\\s+conflict'${nameFilter} loop`,
            `    d := pg_get_functiondef(f.oid);`,
            `    d := regexp_replace(d, 'AS \\$function\\$', E'AS $function$\\n#variable_conflict use_variable');`,
            `    execute d;`,
            `  end loop;`, `end $fix$;`].join('\n'),
          findings: [] });
      }
      fixes.find(f => f.ambiguousCol === col).findings.push(...items.filter(i => /is ambiguous/i.test(i.proof?.observed?.error || '')).map(i => i.id));
      if (items.every(i => /is ambiguous/i.test(i.proof?.observed?.error || ''))) continue;
    }
    // Real users hit an error that isn't about access rules at all (a bug in a
    // function, say): rewriting the policies wouldn't fix it and could quietly
    // remove access someone needs, so say what's wrong and don't guess.
    const notLoop = items.filter(i => !/infinite recursion|is ambiguous|permission denied for table users/i.test(i.proof?.observed?.error || ''));
    const otherErr = notLoop.filter(i => i.class === 'legit' && i.proof?.observed?.error && !/row-level security|permission denied/i.test(i.proof.observed.error) && !/\.legit\.per_user_unique\./.test(i.id));
    if (otherErr.length && otherErr.length === notLoop.length) {
      fixes.push({ table, problems: [legitProblem(items)],
        prompt: [`Fix the error real users hit on "${table}" in my Supabase database.`, `Problem: ${legitProblem(items)}`, `Rule to enforce: the same queries work without errors; don't change who can see or change what.`].join('\n'),
        sql: `-- no automatic fix: the error "${otherErr[0].proof.observed.error.replace(/\n/g, ' ')}" comes from the app's own SQL`, findings: otherErr.map(i => i.id), manual: true });
      continue;
    }
    const authUsersErr = items.some(i => /permission denied for table users/i.test(i.proof?.observed?.error || ''));
    if (authUsersErr) {
      // A policy reads auth.users. Signed-in users can't, so the policy errors;
      // their own email is in their token instead.
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      fixes.push({ table, problems: [legitProblem(items)],
        prompt: [`Fix the row level security on "${table}" in my Supabase database.`, `Problem: ${legitProblem(items)}`, `Rule to enforce: policies read the user's email from auth.jwt() ->> 'email' instead of querying auth.users; who can do what stays the same.`].join('\n'),
        sql: [`do $fix$ declare p record; u text; c text; r text; begin`,
          `  for p in select * from pg_policies where schemaname = 'public' and tablename = ${lit(table)} and (coalesce(qual, '') || coalesce(with_check, '')) ~* 'auth\\.users' loop`,
          `    u := regexp_replace(p.qual, '\\(\\s*SELECT\\s+users\\.email\\s+FROM\\s+auth\\.users\\s+WHERE\\s+\\(?\\s*users\\.id\\s*=\\s*auth\\.uid\\(\\)\\s*\\)?\\s*\\)', '(auth.jwt() ->> ''email'')', 'gi');`,
          `    c := regexp_replace(p.with_check, '\\(\\s*SELECT\\s+users\\.email\\s+FROM\\s+auth\\.users\\s+WHERE\\s+\\(?\\s*users\\.id\\s*=\\s*auth\\.uid\\(\\)\\s*\\)?\\s*\\)', '(auth.jwt() ->> ''email'')', 'gi');`,
          `    select string_agg(quote_ident(y), ', ') into r from unnest(p.roles) y;`,
          `    execute format('drop policy %I on public.%I', p.policyname, p.tablename);`,
          `    execute format('create policy %I on public.%I as %s for %s to %s', p.policyname, p.tablename, p.permissive, p.cmd, r)`,
          `      || coalesce(' using (' || u || ')', '') || coalesce(' with check (' || c || ')', '');`,
          `  end loop;`, `end $fix$;`].join('\n'),
        findings: items.filter(i => /permission denied for table users/i.test(i.proof?.observed?.error || '')).map(i => i.id) });
      if (items.every(i => /permission denied for table users/i.test(i.proof?.observed?.error || ''))) continue;
    }
    const unlooped = items.filter(i => !/infinite recursion/i.test(i.proof?.observed?.error || ''));
    if (t?.membership && t.owner && t.tenant && unlooped.length && unlooped.every(i => i.id.endsWith('.legit.creator_joins'))) {
      const fk = (t.fks || []).find(f => f.col === t.tenant && f.refSchema === 'public');
      const fn = q(`vc_add_creator_to_${t.name}`);
      const prob = `Whoever creates a "${fk?.refTable || 'team'}" never becomes a member of it: no trigger adds them and no policy lets them add themselves, so a new team is invisible to its creator and nobody can ever join it.`;
      const roleCol = t.memberRole ? `, ${q(t.memberRole.col)}` : '';
      // The top role the table allows (owner before admin) for whoever created the group.
  const roleVal = t.memberRole ? `, '${String(t.memberRole.top || t.memberRole.admin).replace(/'/g, "''")}'` : '';
      fixes.push({ table, problems: [prob],
        prompt: [`Fix team creation in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: when a signed-in user creates a ${fk?.refTable || 'team'}, the database adds them to "${table}" as its ${t.memberRole ? `"${t.memberRole.admin}"` : 'first member'}; users still can't add themselves to other teams.`].join('\n'),
        sql: creatorTrigger(t).join('\n'),
        findings: unlooped.map(i => i.id) });
      continue;
    }
    if (t?.owner && legitIds.length && legitIds.every(id => id.endsWith('.legit.new_user_row')) && classes.every(c => c === 'legit')) {
      fixes.push({ table, problems: [legitProblem(items)],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${legitProblem(items)}`, `Rule to enforce: a signed-in user can create their own row in "${table}" (and only their own); keep every other rule.`].join('\n'),
        sql: [`create policy ${q(`${table}_insert_own`)} on public.${q(table)} for insert to authenticated with check (${q(t.owner)} = auth.uid()${emailGuard(t)});`,
          `-- or create the row at signup with a trigger on auth.users`].join('\n'),
        findings: legitIds });
      continue;
    }
    if (t && classes.every(c => c === 'shared_data_write' || (c === 'anon_write' && !t.key))) {
      // Rows that belong to nobody: reads stay as they are, writes only by staff
      // (a policy that checks a staff or admin helper) or the server.
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      const readTo = t.publicRead ? 'anon, authenticated' : 'authenticated';
      fixes.push({ table, problems: [EXPLAIN.shared_data_write],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${EXPLAIN.shared_data_write}`, `Rule to enforce: everyone who can read "${table}" today still can; only staff (through a staff or admin check in the policy) or the server can add, change or delete rows.`].join('\n'),
        sql: [`alter table public.${q(table)} enable row level security;`,
          `do $fix$ declare p record; r text; begin`,
          `  for p in select * from pg_policies where schemaname = 'public' and tablename = ${lit(table)} and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')`,
          `    and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) !~* '(admin|staff|manager|moderator|is_[a-z_]+\\()' loop`,
          `    execute format('drop policy %I on public.%I', p.policyname, p.tablename);`,
          `    if p.cmd = 'ALL' then`,
          `      select string_agg(quote_ident(y), ', ') into r from unnest(p.roles) y;`,
          `      execute format('create policy %I on public.%I for select to %s using (%s)', p.policyname, p.tablename, r, coalesce(p.qual, 'true'));`,
          `    end if;`,
          `  end loop;`,
          `  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = ${lit(table)} and cmd in ('SELECT', 'ALL')) then`,
          `    execute ${lit(`create policy ${q(`${table}_read`)} on public.${q(table)} for select to ${readTo} using (true)`)};`,
          `  end if;`,
          `end $fix$;`].join('\n'),
        findings: items.map(i => i.id) });
      continue;
    }
    if (t?.shareTable && t.owner && classes.some(c => ['share_foreign_item', 'anon_write', 'cross_user_write', 'token_enumeration'].includes(c))) {
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      const own = `${q(t.owner)} = auth.uid()`;
      const parents = (t.fks || []).filter(f => f.refSchema === 'public' && f.refTable !== t.name && schema.find(x => x.name === f.refTable)?.owner);
      const ownsItem = parents.map(f => `exists (select 1 from public.${q(f.refTable)} i where i.${q(f.refCol)} = ${q(f.col)} and i.${q(schema.find(x => x.name === f.refTable).owner)} = auth.uid())`);
      const tokenCol = t.columns.find(c => /token|code|slug|key|hash/i.test(c));
      fixes.push({ table, problems: [...new Set(classes.map(c => EXPLAIN[c]).filter(Boolean))],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${[...new Set(classes.map(c => EXPLAIN[c]).filter(Boolean))].join(' ')}`,
          `Rule to enforce: only the person who created a share can see, change or revoke it, and only for items they own; nobody can list shares; someone with a link opens exactly one shared item by its token through a security-definer function.`].join('\n'),
        sql: [`alter table public.${q(table)} enable row level security;`, dropAll('public', table),
          `create policy ${q(`${table}_select_own`)} on public.${q(table)} for select to authenticated using (${own});`,
          `create policy ${q(`${table}_insert_own`)} on public.${q(table)} for insert to authenticated with check (${[own, ...ownsItem].join(' and ')});`,
          `create policy ${q(`${table}_update_own`)} on public.${q(table)} for update to authenticated using (${own}) with check (${[own, ...ownsItem].join(' and ')});`,
          `create policy ${q(`${table}_delete_own`)} on public.${q(table)} for delete to authenticated using (${own});`,
          ...(tokenCol ? [`create or replace function public.${q(`get_${table}_by_token`)}(p_token text) returns setof public.${q(table)} language sql stable security definer set search_path = public as $$`,
            `  select * from public.${q(table)} where ${q(tokenCol)}::text = p_token;`, `$$;`,
            `grant execute on function public.${q(`get_${table}_by_token`)}(text) to anon, authenticated;`] : [])].join('\n'),
        findings: items.map(i => i.id) });
      continue;
    }
    if (t && classes.every(c => c === 'foreign_parent_write')) {
      const cols = [...new Set(items.map(i => i.id.split('.').pop()))];
      const fks = (t.fks || []).filter(f => cols.includes(f.col));
      const conds = fks.map(f => `${q(f.col)} is null or exists (select 1 from public.${q(f.refTable)} p where p.${q(f.refCol)} = ${q(f.col)})`);
      const rule = `a row can only point at a ${fks.map(f => `"${f.refTable}"`).join(' / ')} row its author can see`;
      fixes.push({ table, problems: [EXPLAIN.foreign_parent_write],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${EXPLAIN.foreign_parent_write}`, `Rule to enforce: ${rule}; keep every existing rule.`].join('\n'),
        // A restrictive policy is ANDed with the existing ones, so nothing that
        // works today stops working except pointing at other people's items. The
        // lookup runs with the caller's own access, so team members can still
        // attach to items their team shares.
        sql: [`create policy ${q(`${table}_parent_visible_insert`)} on public.${q(table)} as restrictive for insert to authenticated with check (${conds.map(c => `(${c})`).join(' and ')});`,
          `create policy ${q(`${table}_parent_visible_update`)} on public.${q(table)} as restrictive for update to authenticated with check (${conds.map(c => `(${c})`).join(' and ')});`].join('\n'),
        findings: items.map(i => i.id) });
      continue;
    }
    // A share-lookup function handing out the author's email: the fix is to
    // return fewer columns, which only the app's author can decide.
    if (!t && items.every(i => /\.rpc\.reveals_email\./.test(i.id))) {
      const prob = `The share-link lookup "${table}" returns the author's email to anyone with a link.`;
      fixes.push({ table, manual: true, problems: [prob],
        prompt: [`Fix the "${table}" function in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: the function returns only what a visitor needs to see the shared item (no email, phone or account ids).`].join('\n'),
        sql: `-- no automatic fix: change "${table}" to leave the email out of what it returns`, findings: items.map(i => i.id) });
      continue;
    }
    const staffUpd = items.filter(i => /\.legit\.staff_update\./.test(i.id));
    if (t && staffUpd.length && staffUpd.length === items.length) {
      // Staff can already read these rows through a staff policy; let the same
      // staff check update them.
      const read = (t.policies || []).find(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && /admin|staff|manager|moderator|is_[a-z_]+\s*\(|has_role/i.test(p.text) && !new RegExp(`\\b${t.owner || '__none__'}\\b`).test(p.text));
      const cond = t.managerCheck || (read ? read.text.trim() : null);
      const prob = `Staff can see "${table}" rows but can't update them (no update policy lets a staff member change another user's row), so the staff feature doesn't work.`;
      fixes.push({ table, problems: [prob], manual: !cond,
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: staff (the same check that lets them read "${table}") can update its rows; customers keep only what they have.`].join('\n'),
        sql: cond ? `create policy ${q(`${table}_staff_update`)} on public.${q(table)} for update to authenticated using (${cond}) with check (${cond});` : `-- no staff read policy found to reuse: add an update policy for staff on "${table}"`,
        findings: staffUpd.map(i => i.id) });
      continue;
    }
    const raise = items.filter(i => /\.invitee\.raise_role\./.test(i.id));
    if (t?.owner && raise.length && raise.length === items.length) {
      const roleCol = t.columns.find(c => /^(role|member_role|access_level|permission)$/i.test(c));
      const fn = q(`vc_lock_${table}_${roleCol}`);
      const prob = `The person an invitation is for can raise the role it grants (member to owner) before accepting it, and join the team as its owner.`;
      fixes.push({ table, problems: [prob],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: only whoever sent an invitation can change its "${roleCol}"; the invitee can only accept it.`].join('\n'),
        sql: [`create or replace function public.${fn}() returns trigger language plpgsql as $lock$`,
          `begin`,
          `  if current_user in ('anon', 'authenticated') and new.${q(roleCol)} is distinct from old.${q(roleCol)} and old.${q(t.owner)} is distinct from auth.uid() then`,
          `    raise exception 'permission denied: only the sender can change an invitation''s ${roleCol}';`,
          `  end if;`, `  return new;`, `end $lock$;`,
          `drop trigger if exists ${fn} on public.${q(table)};`,
          `create trigger ${fn} before update on public.${q(table)} for each row execute function public.${fn}();`].join('\n'),
        findings: raise.map(i => i.id) });
      continue;
    }
    const perUser = items.filter(i => /\.legit\.per_user_unique\./.test(i.id));
    if (t?.owner && perUser.length && perUser.length === items.length) {
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      const cols = [...new Set(perUser.map(i => i.id.split('.').pop()))];
      const prob = `${cols.map(c => `"${c}"`).join(', ')} must be unique across every user of the app, so the second user who picks a value (INV-001) gets an error, and anyone can block values other users will need.`;
      fixes.push({ table, problems: [prob],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: ${cols.map(c => `"${c}"`).join(', ')} is unique per user, not across the app.`].join('\n'),
        sql: [`do $fix$ declare c record; begin`,
          `  for c in select con.conname from pg_constraint con join pg_class cl on cl.oid = con.conrelid join pg_namespace n on n.oid = cl.relnamespace`,
          `    where n.nspname = 'public' and cl.relname = ${lit(table)} and con.contype = 'u' and array_length(con.conkey, 1) = 1`,
          `      and (select attname from pg_attribute where attrelid = con.conrelid and attnum = con.conkey[1]) in (${cols.map(lit).join(', ')}) loop`,
          `    execute format('alter table public.%I drop constraint %I', ${lit(table)}, c.conname);`,
          `  end loop;`, `end $fix$;`,
          ...cols.map(c => `alter table public.${q(table)} add constraint ${q(`${table}_${c}_per_user`)} unique (${q(t.owner)}, ${q(c)});`)].join('\n'),
        findings: perUser.map(i => i.id) });
      continue;
    }
    const readBack = items.filter(i => i.id.endsWith('.legit.create_and_read_back'));
    if (t?.owner && readBack.length && readBack.length === items.length) {
      const prob = `Whoever creates a "${table}" row can't read it back in the same call (insert().select() fails with a row level security error), because they can only see rows of teams they are already a member of.`;
      fixes.push({ table, problems: [prob],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${prob}`, `Rule to enforce: the creator can always read the "${table}" rows they created, in addition to the existing rules.`].join('\n'),
        sql: `create policy ${q(`${table}_creator_reads`)} on public.${q(table)} for select to authenticated using (${q(t.owner)} = auth.uid());`,
        findings: readBack.map(i => i.id) });
      continue;
    }
    if (classes.every(c => c === 'negative_value')) {
      const cols = [...new Set(items.map(i => i.id.split('.').pop()))];
      fixes.push({ table, problems: [EXPLAIN.negative_value],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${EXPLAIN.negative_value}`, `Rule to enforce: ${cols.map(c => `"${c}"`).join(' and ')} can never be negative.`].join('\n'),
        sql: cols.map(c => `alter table public.${q(table)} add constraint ${q(`${table}_${c}_not_negative`)} check (${q(c)} >= 0) not valid;`).join('\n')
          + `\n-- "not valid" leaves existing rows alone; run "alter table ... validate constraint" once they're cleaned up`,
        findings: items.map(i => i.id) });
      continue;
    }
    if (classes.every(c => c === 'public_bucket')) {
      const id = table.replace(/^storage\.buckets\//, '');
      fixes.push({ table, problems: [EXPLAIN.public_bucket],
        prompt: [`Make the "${id}" storage bucket private in my Supabase project.`, `Problem: ${EXPLAIN.public_bucket}`, `Rule to enforce: files in "${id}" are only readable by their owner (storage policies on storage.objects), and the app shows them through signed URLs that expire.`].join('\n'),
        sql: [`update storage.buckets set public = false where id = '${id.replace(/'/g, "''")}';`,
          `-- then serve files with createSignedUrl() instead of getPublicUrl(), and set public = false for this bucket in supabase/config.toml too`].join('\n'),
        findings: items.map(i => i.id) });
      continue;
    }
    if (classes.every(c => c === 'service_key_exposed')) {
      const where = items.map(i => i.proof.sql).join(', ');
      fixes.push({ table, kind: 'code', problems: [EXPLAIN.service_key_exposed],
        prompt: [`Remove the Supabase service-role key from ${table} in my app.`, `Problem: ${EXPLAIN.service_key_exposed} Found at ${where}.`,
          `Rule to enforce: browser code only ever uses the anon (publishable) key; anything that needs the service-role key runs on the server (an API route or an Edge Function) and reads it from a server-only environment variable with no VITE_/NEXT_PUBLIC_/REACT_APP_ prefix.`,
          `Then rotate the key in the Supabase dashboard (Project Settings, API keys): the exposed one must be treated as public.`].join('\n'),
        sql: `-- not a database change: move the key to the server, then rotate it in the Supabase dashboard`,
        findings: items.map(i => i.id) });
      continue;
    }
    if (recursion) {
      const fixed = fixes.find(f => f.loopTable === loopTable);
      const hits = items.filter(i => /infinite recursion/i.test(i.proof?.observed?.error || '')).map(i => i.id);
      if (fixed) fixed.findings.push(...hits);
      else fixes.push(makeRecursionFix(loopTable, hits));
      // Only recursion here: its fix covers it. Real leaks still get their own fix.
      if (items.every(i => /infinite recursion/i.test(i.proof?.observed?.error || ''))) continue;
    }
    if (classes.includes('privileged_tamper') && t?.tamper?.length) {
      const cols = [...new Set(items.filter(i => i.class === 'privileged_tamper').map(i => i.id.split('.').pop()))];
      // No staff function found in the policies: only the server may change them
      // (replace false with the app's own staff check to let staff do it too).
      // Staff are whoever the app's staff table lists (checked through a
      // security-definer helper, since staff tables are usually unreadable).
      const P = schema.find(x => x.privilegeProbe && x.owner && !x.skipCheck);
      const staffHelper = !t.managerCheck && P ? [`create or replace function public.vc_is_staff() returns boolean language sql stable security definer set search_path = public as $h$ select exists (select 1 from public.${q(P.name)} where ${q(P.owner)} = auth.uid()) $h$;`] : [];
      const allowed = t.managerCheck || (staffHelper.length ? 'public.vc_is_staff()' : 'false');
      // Named after the columns it locks, so a later fix for another column adds a
      // lock instead of replacing an earlier one (which would reopen it).
      const fn = q(`vc_lock_${t.name}_${cols.join('_')}`.slice(0, 63));
      fixes.push({ table, problems: [EXPLAIN.privileged_tamper],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${EXPLAIN.privileged_tamper}`, `Rule to enforce: ordinary users can't change ${cols.map(c => `"${c}"`).join(', ')} on their own rows; only staff (${allowed}) or the server can. Keep everything else they can do.`].join('\n'),
        // New rows get the column's own default for status, flags and counters
        // (an order starts "pending", a review starts unverified with 0 votes);
        // changes afterwards are staff-only.
        sql: [...staffHelper, `create or replace function public.${fn}() returns trigger language plpgsql as $lock$`,
          `begin`,
          `  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and not coalesce(${allowed}, false) then`,
          `    if tg_op = 'INSERT' then`,
          ...cols.map(c => t.tamper.find(x => x.col === c)).filter(x => x && x.kind !== 'money' && x.defaultExpr).map(x => `      new.${q(x.col)} := ${x.defaultExpr};`),
          `    else`,
          ...cols.map(c => `      if new.${q(c)} is distinct from old.${q(c)} then raise exception 'permission denied: only staff can change ${c}'; end if;`),
          `    end if;`,
          `  end if;`, `  return new;`, `end $lock$;`,
          `drop trigger if exists ${fn} on public.${q(table)};`,
          `create trigger ${fn} before insert or update on public.${q(table)} for each row execute function public.${fn}();`].join('\n'),
        findings: items.filter(i => i.class === 'privileged_tamper').map(i => i.id) });
      if (items.every(i => i.class === 'privileged_tamper')) continue;
    }
    if (classes.includes('team_self_promotion') && t?.memberRole) {
      const R = q(t.memberRole.col);
      const fn = q(`vc_lock_${t.name}_own_role`);
      fixes.push({ table, problems: [EXPLAIN.team_self_promotion],
        prompt: [`Fix the "${table}" table in my Supabase database.`, `Problem: ${EXPLAIN.team_self_promotion}`, `Rule to enforce: nobody can change their own "${t.memberRole.col}"; only a team owner or admin can change other members' roles.`].join('\n'),
        sql: [`create or replace function public.${fn}() returns trigger language plpgsql as $lock$`,
          `begin`,
          `  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and new.${q(t.owner)} = auth.uid() and new.${R} is distinct from old.${R} then`,
          `    raise exception 'permission denied: you can''t change your own role';`,
          `  end if;`, `  return new;`, `end $lock$;`,
          `drop trigger if exists ${fn} on public.${q(table)};`,
          `create trigger ${fn} before update on public.${q(table)} for each row execute function public.${fn}();`].join('\n'),
        findings: items.filter(i => i.class === 'team_self_promotion').map(i => i.id) });
      if (items.every(i => i.class === 'team_self_promotion')) continue;
    }
    const onlyRole = classes.every(c => c === 'self_grant_admin');
    const onlySecret = classes.every(c => c === 'public_secret');
    const onlyView = classes.every(c => c === 'view_bypass');
    const onlyTokens = classes.every(c => c === 'token_enumeration');
    const onlyRpc = classes.every(c => c === 'rpc_leak' || c === 'rpc_write');
    const onlyDefiner = classes.every(c => c === 'definer_exposed');
    const onlySecretBypass = classes.every(c => c === 'secret_bypass');
    const onlySensitive = classes.every(c => c === 'declared_sensitive');
    if (onlyRole && t && !t.role && t.privilegeProbe) {
      // Being in this table is the privilege: only the server adds rows.
      const who = t.owner ? `${q(t.owner)} = auth.uid()` : 'false';
      rule = `users can see whether they are in "${table}", but only the server (or a security-definer function an admin calls) can add, change or remove rows`;
      sql = [`alter table public.${q(table)} enable row level security;`, dropAll('public', table),
        `create policy ${q(`${table}_select_own`)} on public.${q(table)} for select to authenticated using (${who});`];
    } else if (onlySecretBypass) {
      // A parameter named like a column: in SQL the column wins, so the lookup
      // matches every row. Refer to the parameter by position instead.
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      rule = `"${table}" only returns the item whose secret matches the one it was given`;
      sql = [`do $fix$ declare f record; d text; head text; body text; i int; begin`,
        `  for f in select p.oid, p.proargnames from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = ${lit(table)} loop`,
        `    d := pg_get_functiondef(f.oid);`,
        `    head := split_part(d, 'AS $function$', 1); body := substr(d, length(head) + 1);`,
        `    for i in 1 .. coalesce(array_length(f.proargnames, 1), 0) loop`,
        `      body := regexp_replace(body, '([^.a-z_])' || f.proargnames[i] || '([^a-z0-9_]|$)', '\\1$' || i || '\\2', 'gi');`,
        `    end loop;`,
        `    execute head || body;`,
        `  end loop;`, `end $fix$;`];
    } else if (onlyDefiner) {
      const roles = [...new Set(items.map(i => i.proof?.role).filter(Boolean))];
      rule = `only the server (service_role) can run "${table}"`;
      sql = [`do $$ declare f record; begin`,
        `  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = '${table.replace(/'/g, "''")}' loop`,
        `    execute format('revoke execute on function %s from ${(roles.length ? roles : ['anon', 'authenticated']).join(', ')}', f.sig);`,
        `  end loop;`, `end $$;`];
    } else if (onlyRpc) {
      rule = `the function "${table}" only returns what the caller could read anyway: it runs with the caller's rights so row level security applies, or it checks auth.uid() itself`;
      sql = [`do $$ declare f record; begin`,
        `  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = '${table.replace(/'/g, "''")}' loop`,
        `    execute format('alter function %s security invoker', f.sig);`,
        `  end loop;`, `end $$;`,
        `-- if it must bypass row level security (a lookup by share token), keep it security definer and filter by auth.uid() or the token inside it instead`];
    } else if (onlyTokens && t) {
      const tokenCol = t.columns.find(c => /token|code|slug|key|hash/i.test(c)) || '<token column>';
      rule = `nobody can list "${table}" rows or their tokens; a person with a link looks up exactly one item by its token through a security-definer function`;
      const lit = v => `'${String(v).replace(/'/g, "''")}'`;
      // Row level security was off: turn it on with the table's own access rule
      // so its users keep working, instead of only removing listing policies.
      const base = !t.rls ? keyPolicies(t, membership) : null;
      sql = [...(base || [`alter table public.${q(table)} enable row level security;`,
        `-- drop the select policies that let anyone list rows ("using (true)" or "using (<token> is not null)"); owners keep their own access`,
        `do $$ declare p record; begin`,
        `  for p in select policyname from pg_policies where schemaname = 'public' and tablename = ${lit(table)} and cmd in ('SELECT', 'ALL')`,
        `    and (qual ~* '^\\(*\\s*true\\s*\\)*$' or (qual ~* 'is not null' and qual !~* 'auth\\.uid')) loop`,
        `    execute format('drop policy %I on public.%I', p.policyname, ${lit(table)});`,
        `  end loop;`, `end $$;`,
        // Policies that open shared rows some other way ("is_shared = true", or
        // "auth.uid() = user_id or is_shared") still let anyone list them: cap
        // every read at the owner (and staff) with a restrictive policy.
        ...(t.owner ? [`drop policy if exists "vc_only_owner_lists" on public.${q(table)};`,
          `create policy "vc_only_owner_lists" on public.${q(table)} as restrictive for select to anon, authenticated using (${q(t.owner)} = auth.uid()${t.managerCheck ? ` or ${t.managerCheck}` : ''});`] : [])]),
        `-- a person with a link reads exactly one item through this function:`,
        `create or replace function public.${q(`get_${table}_by_token`)}(p_token text) returns setof public.${q(table)} language sql stable security definer set search_path = public as $$`,
        `  select * from public.${q(table)} where ${q(tokenCol)}::text = p_token;`, `$$;`,
        `grant execute on function public.${q(`get_${table}_by_token`)}(text) to anon, authenticated;`];
    } else if (onlyView) {
      rule = `the view "${table}" respects the row level security of the tables it reads, so each person sees only what they could see in those tables`;
      sql = [`alter view public.${q(table)} set (security_invoker = true);`,
        `-- a view over auth.users can't be made safe this way: drop it and look users up through a security-definer function that returns only what's needed`];
    } else if (onlySensitive && t) {
      rule = `other users' personal data in "${table}" (emails, phone numbers, addresses) is not readable; expose a view or function with only the public columns and keep "${table}" owner-only`;
      sql = [`-- keep "${table}" owner-only and publish only non-personal columns, for example:`,
        `-- create view public.${q(table + '_public')} with (security_invoker = true) as select <non-personal columns> from public.${q(table)};`,
        ...(t.owner ? ownerPolicies(t) : [])];
    } else if (onlySecret && t) {
      rule = `"${t.name}" is not readable by everyone; look a row up by its token through a security-definer function that takes the token and returns only that row, and stop declaring "${t.name}" public`;
      sql = [
        `-- remove any "using (true)" select policy on public.${q(t.name)}, keep it owner-only, and expose lookups like:`,
        `-- create function public.get_shared_by_token(p_token text) returns setof public.${q(t.name)} language sql stable security definer set search_path = public as $$ select * from public.${q(t.name)} where <token column> = p_token $$;`,
        ...(t.owner ? ownerPolicies(t) : []),
      ];
    } else if (onlyRole && t?.role) {
      rule = `users can't change their own "${t.role.col}"; only the server (or a security-definer function an admin calls) can grant roles, and new rows get "${t.role.low}"`;
      sql = roleLock(t);
    } else if (table === 'storage.objects') {
      rule = 'only the uploader can read, change or delete their files';
      sql = [
        dropAll('storage', 'objects'),
        `create policy "objects_owner_only" on storage.objects for all to authenticated using (owner = auth.uid()) with check (owner = auth.uid());`,
      ];
    } else if (t && t.membership && t.owner) {
      rule = `users can see their own memberships, and only the server (not users) can add or change memberships`;
      sql = [
        `alter table public.${q(t.name)} enable row level security;`,
        dropAll('public', t.name),
        `create policy ${q(`${t.name}_select_own`)} on public.${q(t.name)} for select to authenticated using (${q(t.owner)} = auth.uid());`,
      ];
    } else if (t && t.owner && !t.tenant) {
      rule = `each row belongs to the user in "${t.owner}", and only that user can read, create, change or delete it`;
      sql = ownerPolicies(t);
    } else if (t && t.tenant) {
      rule = `rows belong to the organization in "${t.tenant}", and only members of that organization can access them`;
      sql = tenantPolicies(t, membership);
    } else if (t && t.keyKind === 'parent') {
      rule = `a row in "${t.name}" can be read or changed only by someone who can access its "${t.parent}" row`;
      sql = parentPolicies(t);
    } else if (t && classes.every(c => /^anon_/.test(c))) {
      // No column ties rows to a user, so only the anonymous hole can be closed
      // for certain: lock anonymous visitors out and keep signed-in use as it is.
      rule = `anonymous visitors can't read or change "${table}"; signed-in users keep their current access (nothing ties a row to a user yet: add a user_id column referencing auth.users to limit each user to their own rows)`;
      sql = [`alter table public.${q(table)} enable row level security;`,
        ...(t.policies.length ? [] : [`create policy ${q(`${table}_signed_in`)} on public.${q(table)} for all to authenticated using (true) with check (true);`]),
        `revoke all on table public.${q(table)} from anon;`,
        `-- if "${table}" is meant to be public (a catalog), declare it instead: public_tables: ["${table}: who reads it and why"]`];
    } else {
      rule = 'decide who should access this table, then enable row level security with matching policies';
      sql = [`alter table public.${q(table)} enable row level security;`];
    }
    if (!onlyRole && classes.includes('self_grant_admin') && t?.role) {
      rule += `; users also can't change their own "${t.role.col}"`;
      sql.push(...roleLock(t));
    }
    if (classes.includes('trusts_user_metadata')) {
      sql.unshift('-- remove any policy that reads auth.jwt() -> \'user_metadata\'; use a roles table or app_metadata instead');
    }

    const prompt = [
      `Fix the security of the "${table}" table in my Supabase database.`,
      `Problem: ${problems.join(' ')}`,
      `Rule to enforce: ${rule}.`,
      `Replace the existing row level security policies on "${table}" with policies that enforce exactly that rule, and don't change any other table.`,
    ].join('\n');

    // Replacing a membership table's policies (or finding its creators locked
    // out) also has to keep "whoever creates a team joins it" working.
    if (t?.membership && t.owner && t.tenant && (sql.some(l => /drop policy/i.test(l)) || legitIds.some(id => id.endsWith('.legit.creator_joins')))) sql.push(...creatorTrigger(t));
    fixes.push({ table, problems, prompt, sql: sql.join('\n'), findings: items.map(i => i.id) });
  }
  return fixes;
}
