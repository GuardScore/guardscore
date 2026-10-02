-- verified-changes remote gauntlet: 13_secure_auto

select vc.reset();

-- The secure version of 10 + 12, with no seed and no manifest hints:
-- teams/projects/tasks scoped by membership, profile roles locked by a trigger,
-- a share-links table that grants access on purpose.
create extension if not exists "uuid-ossp";
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'user' check (role in ('user', 'admin')),
  is_private boolean not null default false
);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select to authenticated using (id = (select auth.uid()));
create policy "update own" on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));
create or replace function public.protect_role() returns trigger language plpgsql as $$
begin
  if new.role is distinct from old.role and not public.is_admin() then
    raise exception 'Only admins can change roles';
  end if;
  return new;
end $$;
create trigger protect_role before update on public.profiles for each row execute function public.protect_role();
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create table public.teams (id uuid primary key default uuid_generate_v4(), name text not null, created_by uuid references auth.users default auth.uid());
create table public.team_members (
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  primary key (team_id, user_id)
);
create table public.projects (id bigint generated always as identity primary key, team_id uuid not null references public.teams, name text not null);
create table public.tasks (id uuid primary key default gen_random_uuid(), project_id bigint not null references public.projects on delete cascade, title text not null, status text not null check (status in ('todo', 'doing', 'done')));
create table public.task_share_links (token text primary key, task_id uuid not null references public.tasks);
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;
alter table public.task_share_links enable row level security;

create or replace function public.is_member(t uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.team_members where team_id = t and user_id = auth.uid());
$$;
create policy "members read" on public.teams for select to authenticated using (public.is_member(id) or created_by = auth.uid());
create policy "members update" on public.teams for update to authenticated using (public.is_member(id)) with check (public.is_member(id));
create policy "create own team" on public.teams for insert to authenticated with check (created_by = auth.uid());
create policy "own memberships" on public.team_members for select to authenticated using (user_id = auth.uid());
create policy "members projects" on public.projects for all to authenticated using (public.is_member(team_id)) with check (public.is_member(team_id));
create policy "members tasks" on public.tasks for all to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id))
  with check (exists (select 1 from public.projects p where p.id = project_id));
create policy "members links" on public.task_share_links for all to authenticated
  using (exists (select 1 from public.tasks t where t.id = task_id)) with check (exists (select 1 from public.tasks t where t.id = task_id));

-- Adds the creator as owner when a team is made.
create or replace function public.add_creator() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.team_members (team_id, user_id, role) values (new.id, auth.uid(), 'owner'); return new; end $$;
create trigger add_creator after insert on public.teams for each row execute function public.add_creator();


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;



select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."teams" ("id", "name", "created_by") values ('00000000-0000-4000-8000-0000000000a1', 'teams alice 1', '00000000-0000-4000-8000-00000000000a');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."teams" ("id", "name", "created_by") values ('00000000-0000-4000-8000-0000000000b1', 'teams bob 2', '00000000-0000-4000-8000-00000000000b');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."projects" ("id", "team_id", "name") overriding system value values (1003, '00000000-0000-4000-8000-0000000000a1', 'projects alice 4');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."projects" ("id", "team_id", "name") overriding system value values (1005, '00000000-0000-4000-8000-0000000000b1', 'projects bob 6');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."tasks" ("id", "project_id", "title", "status") values ('00000000-0000-4000-8000-f00000000007', '1003', 'tasks alice 8', 'todo');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."tasks" ("id", "project_id", "title", "status") values ('00000000-0000-4000-8000-f00000000009', '1005', 'tasks bob 10', 'todo');
select set_config('request.jwt.claims', '', false);

select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'profiles.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."profiles"', 'count'),
  (1, 'profiles.anon.update', 'anon', '{"role":"anon"}', 'update public."profiles" set "id" = "id" where true', 'affected'),
  (2, 'profiles.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."profiles" where true', 'affected'),
  (3, 'profiles.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'profiles.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'profiles.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "id" = "id" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'profiles.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'profiles.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "full_name" = (jsonb_populate_record(null::public."profiles", ''{"full_name":null}''::jsonb))."full_name"', 'affected'),
  (8, 'profiles.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."profiles"', 'affected'),
  (9, 'profiles.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."profiles" ("id", "role", "full_name", "is_private") select "id", "role", "full_name", "is_private" from jsonb_populate_record(null::public."profiles", ''{"id":"00000000-0000-4000-8000-00000000000a","role":"user","full_name":null,"is_private":false}''::jsonb)', 'affected'),
  (10, 'profiles.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."profiles" ("id", "role", "full_name", "is_private") select "id", "role", "full_name", "is_private" from jsonb_populate_record(null::public."profiles", ''{"id":"00000000-0000-4000-8000-00000000000a","role":"user","full_name":null,"is_private":false}''::jsonb)', 'affected'),
  (11, 'profiles.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."profiles" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'profiles.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."profiles" set "id" = "id" where "id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (13, 'profiles.self_grant_admin.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'with u as (update public."profiles" set "role" = ''admin'' where "id" = ''00000000-0000-4000-8000-00000000000b'' returning "role") select count(*) as n from u where "role"::text = ''admin''', 'count'),
  (14, 'projects.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."projects"', 'count'),
  (15, 'projects.anon.update', 'anon', '{"role":"anon"}', 'update public."projects" set "team_id" = "team_id" where true', 'affected'),
  (16, 'projects.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."projects" where true', 'affected'),
  (17, 'projects.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (18, 'projects.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (19, 'projects.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "team_id" = "team_id" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (20, 'projects.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (21, 'projects.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "name" = (jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4"}''::jsonb))."name"', 'affected'),
  (22, 'projects.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects"', 'affected'),
  (23, 'projects.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (24, 'projects.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (25, 'projects.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (26, 'projects.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (27, 'projects.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "team_id" = "team_id" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (28, 'tasks.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."tasks"', 'count'),
  (29, 'tasks.anon.update', 'anon', '{"role":"anon"}', 'update public."tasks" set "project_id" = "project_id" where true', 'affected'),
  (30, 'tasks.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."tasks" where true', 'affected'),
  (31, 'tasks.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''1003''', 'count'),
  (32, 'tasks.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''1003''', 'count'),
  (33, 'tasks.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."tasks" set "project_id" = "project_id" where "project_id" = ''1003''', 'affected'),
  (34, 'tasks.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."tasks" where "project_id" = ''1003''', 'affected'),
  (35, 'tasks.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."tasks" set "title" = (jsonb_populate_record(null::public."tasks", ''{"title":"tasks alice 8"}''::jsonb))."title"', 'affected'),
  (36, 'tasks.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."tasks"', 'affected'),
  (37, 'tasks.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."tasks" ("title", "status", "project_id") select "title", "status", "project_id" from jsonb_populate_record(null::public."tasks", ''{"title":"tasks alice 8","status":"todo","project_id":"1003"}''::jsonb)', 'affected'),
  (38, 'tasks.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."tasks" ("title", "status", "project_id") select "title", "status", "project_id" from jsonb_populate_record(null::public."tasks", ''{"title":"tasks alice 8","status":"todo","project_id":"1003"}''::jsonb)', 'affected'),
  (39, 'tasks.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''1003''', 'count'),
  (40, 'tasks.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."tasks" ("title", "status", "project_id") select "title", "status", "project_id" from jsonb_populate_record(null::public."tasks", ''{"title":"tasks alice 8","status":"todo","project_id":1003}''::jsonb)', 'affected'),
  (41, 'tasks.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."tasks" set "project_id" = "project_id" where "project_id" = ''1003''', 'affected'),
  (42, 'team_members.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."team_members"', 'count'),
  (43, 'team_members.anon.update', 'anon', '{"role":"anon"}', 'update public."team_members" set "team_id" = "team_id" where true', 'affected'),
  (44, 'team_members.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."team_members" where true', 'affected'),
  (45, 'team_members.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (46, 'team_members.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (47, 'team_members.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."team_members" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (48, 'team_members.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (49, 'team_members.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."team_members" set "role" = (jsonb_populate_record(null::public."team_members", ''{"role":"owner"}''::jsonb))."role"', 'affected'),
  (50, 'team_members.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."team_members"', 'affected'),
  (51, 'team_members.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (52, 'team_members.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (53, 'team_members.self_join_other_tenant', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000b"}''::jsonb)', 'affected'),
  (54, 'team_members.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (55, 'teams.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."teams"', 'count'),
  (56, 'teams.anon.update', 'anon', '{"role":"anon"}', 'update public."teams" set "name" = "name" where true', 'affected'),
  (57, 'teams.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."teams" where true', 'affected'),
  (58, 'teams.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."teams" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (59, 'teams.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."teams" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (60, 'teams.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "created_by" = "created_by" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (61, 'teams.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."teams" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (62, 'teams.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "name" = (jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1"}''::jsonb))."name"', 'affected'),
  (63, 'teams.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."teams"', 'affected'),
  (64, 'teams.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."teams" ("name", "created_by") select "name", "created_by" from jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1","created_by":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (65, 'teams.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."teams" ("name", "created_by") select "name", "created_by" from jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1","created_by":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (66, 'teams.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."teams" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (67, 'teams.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."teams" ("name", "created_by") select "name", "created_by" from jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1","created_by":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (68, 'teams.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "created_by" = "created_by" where "created_by" = ''00000000-0000-4000-8000-00000000000a''', 'affected')
) as v(ord, id, role, claims, q, judge);