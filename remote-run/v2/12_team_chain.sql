-- verified-changes remote gauntlet: 12_team_chain

select vc.reset();

-- Teams -> projects -> tasks, no seed and no manifest hints. Projects are
-- correctly scoped to team members; tasks check only that you're logged in.
create table public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
create table public.team_members (
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  primary key (team_id, user_id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams on delete cascade,
  name text not null
);
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects on delete cascade,
  title text not null,
  done boolean not null default false
);
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;

create or replace function public.is_member(t uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.team_members where team_id = t and user_id = auth.uid());
$$;
create policy "members read team" on public.teams for select to authenticated using (public.is_member(id));
create policy "members update team" on public.teams for update to authenticated using (public.is_member(id)) with check (public.is_member(id));
create policy "anyone creates a team" on public.teams for insert to authenticated with check (true);
create policy "see own memberships" on public.team_members for select to authenticated using (user_id = auth.uid());
create policy "members use projects" on public.projects for all to authenticated using (public.is_member(team_id)) with check (public.is_member(team_id));
create policy "logged in users use tasks" on public.tasks for all to authenticated using (true) with check (true);


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;



select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."teams" ("id", "name") values ('00000000-0000-4000-8000-0000000000a1', 'teams alice 1');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."teams" ("id", "name") values ('00000000-0000-4000-8000-0000000000b1', 'teams bob 2');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."projects" ("id", "team_id", "name") values ('00000000-0000-4000-8000-f00000000003', '00000000-0000-4000-8000-0000000000a1', 'projects alice 4');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."projects" ("id", "team_id", "name") values ('00000000-0000-4000-8000-f00000000005', '00000000-0000-4000-8000-0000000000b1', 'projects bob 6');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."team_members" ("team_id", "user_id", "role") values ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-00000000000a', 'owner');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."team_members" ("team_id", "user_id", "role") values ('00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-00000000000b', 'owner');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."tasks" ("id", "project_id", "title") values ('00000000-0000-4000-8000-f00000000007', '00000000-0000-4000-8000-f00000000003', 'tasks alice 8');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."tasks" ("id", "project_id", "title") values ('00000000-0000-4000-8000-f00000000009', '00000000-0000-4000-8000-f00000000005', 'tasks bob 10');
select set_config('request.jwt.claims', '', false);

select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'projects.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."projects"', 'count'),
  (1, 'projects.anon.update', 'anon', '{"role":"anon"}', 'update public."projects" set "team_id" = "team_id" where true', 'affected'),
  (2, 'projects.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."projects" where true', 'affected'),
  (3, 'projects.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (4, 'projects.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (5, 'projects.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "team_id" = "team_id" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (6, 'projects.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (7, 'projects.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "name" = (jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4"}''::jsonb))."name"', 'affected'),
  (8, 'projects.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects"', 'affected'),
  (9, 'projects.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (10, 'projects.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (11, 'projects.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (12, 'projects.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "team_id") select "name", "team_id" from jsonb_populate_record(null::public."projects", ''{"name":"projects alice 4","team_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (13, 'projects.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "team_id" = "team_id" where "team_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (14, 'tasks.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."tasks"', 'count'),
  (15, 'tasks.anon.update', 'anon', '{"role":"anon"}', 'update public."tasks" set "project_id" = "project_id" where true', 'affected'),
  (16, 'tasks.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."tasks" where true', 'affected'),
  (17, 'tasks.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''00000000-0000-4000-8000-f00000000003''', 'count'),
  (18, 'tasks.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''00000000-0000-4000-8000-f00000000003''', 'count'),
  (19, 'tasks.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."tasks" set "project_id" = "project_id" where "project_id" = ''00000000-0000-4000-8000-f00000000003''', 'affected'),
  (20, 'tasks.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."tasks" where "project_id" = ''00000000-0000-4000-8000-f00000000003''', 'affected'),
  (21, 'tasks.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."tasks" set "title" = (jsonb_populate_record(null::public."tasks", ''{"title":"tasks alice 8"}''::jsonb))."title"', 'affected'),
  (22, 'tasks.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."tasks"', 'affected'),
  (23, 'tasks.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."tasks" ("done", "title", "project_id") select "done", "title", "project_id" from jsonb_populate_record(null::public."tasks", ''{"done":false,"title":"tasks alice 8","project_id":"00000000-0000-4000-8000-f00000000003"}''::jsonb)', 'affected'),
  (24, 'tasks.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."tasks" ("done", "title", "project_id") select "done", "title", "project_id" from jsonb_populate_record(null::public."tasks", ''{"done":false,"title":"tasks alice 8","project_id":"00000000-0000-4000-8000-f00000000003"}''::jsonb)', 'affected'),
  (25, 'tasks.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."tasks" where "project_id" = ''00000000-0000-4000-8000-f00000000003''', 'count'),
  (26, 'team_members.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."team_members"', 'count'),
  (27, 'team_members.anon.update', 'anon', '{"role":"anon"}', 'update public."team_members" set "team_id" = "team_id" where true', 'affected'),
  (28, 'team_members.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."team_members" where true', 'affected'),
  (29, 'team_members.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (30, 'team_members.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (31, 'team_members.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."team_members" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (32, 'team_members.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (33, 'team_members.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."team_members" set "role" = (jsonb_populate_record(null::public."team_members", ''{"role":"owner"}''::jsonb))."role"', 'affected'),
  (34, 'team_members.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."team_members"', 'affected'),
  (35, 'team_members.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (36, 'team_members.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (37, 'team_members.self_join_other_tenant', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."team_members" ("role", "team_id", "user_id") select "role", "team_id", "user_id" from jsonb_populate_record(null::public."team_members", ''{"role":"owner","team_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000b"}''::jsonb)', 'affected'),
  (38, 'team_members.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."team_members" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (39, 'teams.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."teams"', 'count'),
  (40, 'teams.anon.update', 'anon', '{"role":"anon"}', 'update public."teams" set "name" = "name" where true', 'affected'),
  (41, 'teams.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."teams" where true', 'affected'),
  (42, 'teams.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."teams" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (43, 'teams.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."teams" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (44, 'teams.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "id" = "id" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (45, 'teams.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."teams" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (46, 'teams.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "name" = (jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1"}''::jsonb))."name"', 'affected'),
  (47, 'teams.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."teams"', 'affected'),
  (48, 'teams.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."teams" ("name") select "name" from jsonb_populate_record(null::public."teams", ''{"name":"teams alice 1"}''::jsonb)', 'affected'),
  (49, 'teams.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."teams" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (50, 'teams.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."teams" set "id" = "id" where "id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected')
) as v(ord, id, role, claims, q, judge);