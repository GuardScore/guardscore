-- verified-changes remote gauntlet: 03_update_open

select vc.reset();

create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  display_name text,
  plan text default 'free'
);
alter table public.profiles enable row level security;
create policy "own read" on public.profiles for select to authenticated using (user_id = auth.uid());
create policy "own insert" on public.profiles for insert to authenticated with check (user_id = auth.uid());
-- Bug: the update policy forgot the ownership check.
create policy "update" on public.profiles for update to authenticated using (true);


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.profiles (user_id, display_name) values ('00000000-0000-4000-8000-00000000000a', 'Alice'), ('00000000-0000-4000-8000-00000000000b', 'Bob');


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'profiles.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."profiles"', 'count'),
  (1, 'profiles.anon.update', 'anon', '{"role":"anon"}', 'update public."profiles" set "id" = "id" where true', 'affected'),
  (2, 'profiles.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."profiles" where true', 'affected'),
  (3, 'profiles.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'profiles.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'profiles.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'profiles.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'profiles.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "display_name" = (jsonb_populate_record(null::public."profiles", ''{"display_name":"Alice"}''::jsonb))."display_name"', 'affected'),
  (8, 'profiles.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles"', 'affected'),
  (9, 'profiles.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."profiles" ("plan", "user_id", "display_name") select "plan", "user_id", "display_name" from jsonb_populate_record(null::public."profiles", ''{"plan":"free","user_id":"00000000-0000-4000-8000-00000000000a","display_name":"Alice"}''::jsonb)', 'affected'),
  (10, 'profiles.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."profiles" ("plan", "user_id", "display_name") select "plan", "user_id", "display_name" from jsonb_populate_record(null::public."profiles", ''{"plan":"free","user_id":"00000000-0000-4000-8000-00000000000a","display_name":"Alice"}''::jsonb)', 'affected'),
  (11, 'profiles.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'profiles.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."profiles" ("plan", "user_id", "display_name") select "plan", "user_id", "display_name" from jsonb_populate_record(null::public."profiles", ''{"plan":"free","user_id":"00000000-0000-4000-8000-00000000000a","display_name":"Alice"}''::jsonb)', 'affected'),
  (13, 'profiles.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected')
) as v(ord, id, role, claims, q, judge);