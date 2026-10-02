-- Simplify roles to owner and member only
-- Update constraint on role column
alter table team_members drop constraint team_members_role_check;
alter table team_members add constraint team_members_role_check check (role in ('owner', 'member'));

-- Update any existing admins to members
update team_members set role = 'member' where role = 'admin';

-- Drop and recreate team_members policies - only owners can manage members
drop policy if exists "team_members_select_own" on team_members;

create policy "team_members_select_own" on public.team_members
  for select to authenticated
  using (user_id = auth.uid());

-- Drop and recreate teams policies - only owners can update/delete
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

create policy "Team owners can update teams"
  on teams for update
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = teams.id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));

create policy "Team owners can delete teams"
  on teams for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = teams.id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));

-- Drop and recreate projects policies - only owners can delete
drop policy if exists "Team owners and admins can delete projects" on projects;

create policy "Team owners can delete projects"
  on projects for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = projects.team_id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));

-- Drop and recreate tasks policies - only owners can delete
drop policy if exists "Team owners and admins can delete tasks" on tasks;

create policy "Team owners can delete tasks"
  on tasks for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = (select team_id from projects where projects.id = tasks.project_id)
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));
