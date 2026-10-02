-- Create private schema for security-definer functions
create schema if not exists private;
grant usage on schema private to anon, authenticated;

-- Create security-definer function for team_members to avoid infinite recursion
create or replace function private.team_members_rows()
  returns setof public.team_members
  language sql stable security definer set search_path = pg_catalog, public
  as $f$ select * from public.team_members $f$;

revoke all on function private.team_members_rows() from public;
grant execute on function private.team_members_rows() to anon, authenticated;

-- Drop existing team_members policies to replace them
drop policy "Users can see teams they belong to" on teams;
drop policy "Owners can insert teams" on teams;
drop policy "Owners can update their teams" on teams;
drop policy "Owners can delete their teams" on teams;
drop policy "Team members can see their team members" on team_members;
drop policy "Team owners can manage members" on team_members;
drop policy "Team owners can update members" on team_members;
drop policy "Team owners can delete members" on team_members;
drop policy "Team members can see projects" on projects;
drop policy "Team members can create projects" on projects;
drop policy "Project owners can update" on projects;
drop policy "Project owners can delete" on projects;
drop policy "Team members can see tasks in their projects" on tasks;
drop policy "Team members can create tasks" on tasks;
drop policy "Users can update tasks they created or are assigned to" on tasks;
drop policy "Task creators can delete tasks" on tasks;

-- Re-create teams policies with fixed logic
create policy "Users can see teams they belong to"
  on teams for select
  using (
    auth.uid() = owner_id or
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = teams.id
      and tm.user_id = auth.uid()
    )
  );

create policy "Owners can insert teams"
  on teams for insert
  with check (auth.uid() = owner_id);

create policy "Owners can update their teams"
  on teams for update
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create policy "Owners can delete their teams"
  on teams for delete
  using (auth.uid() = owner_id);

-- Re-create team_members policies with fixed logic
create policy "Team members can see their team members"
  on team_members for select
  using (
    team_id in (
      select team_id from private.team_members_rows() tm where tm.user_id = auth.uid()
    )
  );

create policy "Team owners can manage members"
  on team_members for insert
  with check (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can update members"
  on team_members for update
  using (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can delete members"
  on team_members for delete
  using (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Re-create projects policies with fixed logic
create policy "projects_tenant_members"
  on projects for all to authenticated
  using (team_id in (select team_id from private.team_members_rows() tm where tm.user_id = auth.uid()))
  with check (team_id in (select team_id from private.team_members_rows() tm where tm.user_id = auth.uid()));

create policy "projects_insert_own"
  on projects for insert to authenticated
  with check (owner_id = auth.uid());

create policy "Project owners can update"
  on projects for update
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create policy "Project owners can delete"
  on projects for delete
  using (auth.uid() = owner_id);

-- Re-create tasks policies
create policy "Team members can see tasks in their projects"
  on tasks for select
  using (
    exists (
      select 1 from projects
      join private.team_members_rows() tm on tm.team_id = projects.team_id
      where projects.id = tasks.project_id
      and tm.user_id = auth.uid()
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    exists (
      select 1 from projects
      join private.team_members_rows() tm on tm.team_id = projects.team_id
      where projects.id = project_id
      and tm.user_id = auth.uid()
    )
  );

create policy "Users can update tasks they created or are assigned to"
  on tasks for update
  using (
    auth.uid() = created_by or
    auth.uid() = assignee_id or
    exists (
      select 1 from projects
      where projects.id = tasks.project_id
      and projects.owner_id = auth.uid()
    )
  );

create policy "Task creators can delete tasks"
  on tasks for delete
  using (auth.uid() = created_by);
