-- verified-changes remote gauntlet: 10_self_admin_profile

select vc.reset();

-- Profiles carry a role; an admin check reads it; users may edit their own profile.
-- Nothing stops a user from setting their own role to 'admin'.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text,
  role text not null default 'user' check (role in ('user', 'admin'))
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select to authenticated using (id = auth.uid());
create policy "update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name) values (new.id, split_part(new.email, '@', 1));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text not null
);
alter table public.notes enable row level security;
create policy "own notes or admin" on public.notes for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "insert own" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "update own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "delete own" on public.notes for delete to authenticated using (user_id = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;



select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."notes" ("id", "user_id", "body") values ('00000000-0000-4000-8000-f00000000001', '00000000-0000-4000-8000-00000000000a', 'notes alice 2');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."notes" ("id", "user_id", "body") values ('00000000-0000-4000-8000-f00000000003', '00000000-0000-4000-8000-00000000000b', 'notes bob 4');
select set_config('request.jwt.claims', '', false);

select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'notes.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."notes"', 'count'),
  (1, 'notes.anon.update', 'anon', '{"role":"anon"}', 'update public."notes" set "user_id" = "user_id" where true', 'affected'),
  (2, 'notes.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."notes" where true', 'affected'),
  (3, 'notes.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'notes.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'notes.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'notes.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'notes.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "body" = (jsonb_populate_record(null::public."notes", ''{"body":"notes alice 2"}''::jsonb))."body"', 'affected'),
  (8, 'notes.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes"', 'affected'),
  (9, 'notes.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"notes alice 2","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (10, 'notes.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"notes alice 2","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (11, 'notes.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'notes.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"notes alice 2","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (13, 'notes.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (14, 'profiles.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."profiles"', 'count'),
  (15, 'profiles.anon.update', 'anon', '{"role":"anon"}', 'update public."profiles" set "id" = "id" where true', 'affected'),
  (16, 'profiles.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."profiles" where true', 'affected'),
  (17, 'profiles.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (18, 'profiles.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (19, 'profiles.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "id" = "id" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (20, 'profiles.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (21, 'profiles.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "display_name" = (jsonb_populate_record(null::public."profiles", ''{"display_name":"alice"}''::jsonb))."display_name"', 'affected'),
  (22, 'profiles.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles"', 'affected'),
  (23, 'profiles.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."profiles" ("id", "role", "display_name") select "id", "role", "display_name" from jsonb_populate_record(null::public."profiles", ''{"id":"00000000-0000-4000-8000-00000000000a","role":"user","display_name":"alice"}''::jsonb)', 'affected'),
  (24, 'profiles.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."profiles" ("id", "role", "display_name") select "id", "role", "display_name" from jsonb_populate_record(null::public."profiles", ''{"id":"00000000-0000-4000-8000-00000000000a","role":"user","display_name":"alice"}''::jsonb)', 'affected'),
  (25, 'profiles.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (26, 'profiles.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "id" = "id" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (27, 'profiles.self_grant_admin.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'with u as (update public."profiles" set "role" = ''admin'' where "id" = ''00000000-0000-4000-8000-00000000000b'' returning "role") select count(*) as n from u where "role"::text = ''admin''', 'count')
) as v(ord, id, role, claims, q, judge);