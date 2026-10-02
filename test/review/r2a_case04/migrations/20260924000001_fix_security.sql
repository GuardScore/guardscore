-- Create private schema for security-definer functions
create schema if not exists private;
grant usage on schema private to anon, authenticated;

-- Security-definer function for team_members lookups
create or replace function private.team_members_rows()
returns setof public.team_members
language sql stable security definer set search_path = pg_catalog, public as $f$
select * from public.team_members
$f$;

revoke all on function private.team_members_rows() from public;
grant execute on function private.team_members_rows() to anon, authenticated;

-- Drop existing problematic policies on team_members
drop policy if exists "Users can view team members" on team_members;
drop policy if exists "Team owners and admins can add members" on team_members;
drop policy if exists "Team owners and admins can update members" on team_members;
drop policy if exists "Team owners and admins can remove members" on team_members;

-- New team_members policies - users can only see their own memberships
create policy "team_members_select_own" on public.team_members
  for select to authenticated
  using (user_id = auth.uid());

-- Drop and recreate projects policies to use private schema function
drop policy if exists "Users can view projects in their teams" on projects;
drop policy if exists "Team members can create projects" on projects;
drop policy if exists "Team members can update projects" on projects;
drop policy if exists "Team owners and admins can delete projects" on projects;

create policy "Users can view projects in their teams"
  on projects for select
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = projects.team_id
    and tm.user_id = auth.uid()
  ));

create policy "Team members can create projects"
  on projects for insert
  with check (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = projects.team_id
    and tm.user_id = auth.uid()
  ));

create policy "Team members can update projects"
  on projects for update
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = projects.team_id
    and tm.user_id = auth.uid()
  ));

create policy "Team owners and admins can delete projects"
  on projects for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = projects.team_id
    and tm.user_id = auth.uid()
    and tm.role in ('owner', 'admin')
  ));

-- Drop and recreate tasks policies to use private schema function
drop policy if exists "Users can view tasks in their projects" on tasks;
drop policy if exists "Team members can create tasks" on tasks;
drop policy if exists "Team members can update tasks" on tasks;
drop policy if exists "Team owners and admins can delete tasks" on tasks;

create policy "Users can view tasks in their projects"
  on tasks for select
  using (exists (
    select 1 from projects
    join private.team_members_rows() tm on tm.team_id = projects.team_id
    where projects.id = tasks.project_id
    and tm.user_id = auth.uid()
  ));

create policy "Team members can create tasks"
  on tasks for insert
  with check (exists (
    select 1 from projects
    join private.team_members_rows() tm on tm.team_id = projects.team_id
    where projects.id = tasks.project_id
    and tm.user_id = auth.uid()
  ));

create policy "Team members can update tasks"
  on tasks for update
  using (exists (
    select 1 from projects
    join private.team_members_rows() tm on tm.team_id = projects.team_id
    where projects.id = tasks.project_id
    and tm.user_id = auth.uid()
  ));

create policy "Team owners and admins can delete tasks"
  on tasks for delete
  using (exists (
    select 1 from projects
    join private.team_members_rows() tm on tm.team_id = projects.team_id
    where projects.id = tasks.project_id
    and tm.user_id = auth.uid()
    and tm.role in ('owner', 'admin')
  ));

-- Drop and recreate teams policies to use private schema function
drop policy if exists "Users can view their teams" on teams;
drop policy if exists "Team owners and admins can update teams" on teams;
drop policy if exists "Team owners and admins can delete teams" on teams;

create policy "Users can view their teams"
  on teams for select
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = teams.id
    and tm.user_id = auth.uid()
  ));

create policy "Team owners and admins can update teams"
  on teams for update
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = teams.id
    and tm.user_id = auth.uid()
    and tm.role in ('owner', 'admin')
  ));

create policy "Team owners and admins can delete teams"
  on teams for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = teams.id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));
