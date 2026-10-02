-- verified-changes remote gauntlet: 02_policy_true_any_user

select vc.reset();

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
-- The CVE-2025-48757 pattern: RLS is on and a policy exists, so existence checks pass,
-- but the policy lets any logged-in user see everyone's rows.
create policy "authenticated can read" on public.notes for select to authenticated using (true);
create policy "authenticated can insert" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "owner can update" on public.notes for update to authenticated using (user_id = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.notes (user_id, body) values ('00000000-0000-4000-8000-00000000000a', 'alice private note'), ('00000000-0000-4000-8000-00000000000b', 'bob private note');


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'notes.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."notes"', 'count'),
  (1, 'notes.anon.update', 'anon', '{"role":"anon"}', 'update public."notes" set "id" = "id" where true', 'affected'),
  (2, 'notes.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."notes" where true', 'affected'),
  (3, 'notes.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'notes.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'notes.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'notes.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'notes.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "body" = (jsonb_populate_record(null::public."notes", ''{"body":"alice private note"}''::jsonb))."body"', 'affected'),
  (8, 'notes.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes"', 'affected'),
  (9, 'notes.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (10, 'notes.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (11, 'notes.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'notes.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (13, 'notes.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected')
) as v(ord, id, role, claims, q, judge);