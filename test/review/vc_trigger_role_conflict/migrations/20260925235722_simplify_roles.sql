-- Simplify roles to Owner and Member
-- Owner: manages team and members
-- Member: works on tasks and projects

-- Update role check constraint
alter table team_members drop constraint if exists team_members_role_check;
alter table team_members add constraint team_members_role_check check (role in ('owner', 'member'));

-- Update default role for new members
alter table team_members alter column role set default 'member';

-- Update existing 'admin' roles to 'owner'
update team_members set role = 'owner' where role = 'admin';

-- Simplify team RLS policies
-- Drop old policies
drop policy if exists "Users can view teams they're members of" on teams;
drop policy if exists "Users can create teams" on teams;
drop policy if exists "Team owners can update their teams" on teams;
drop policy if exists "Team owners can delete their teams" on teams;

-- Create simplified team policies
create policy "users_can_view_their_teams"
  on teams for select
  using (
    auth.uid() = created_by or
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
    )
  );

create policy "users_can_create_teams"
  on teams for insert
  with check (auth.uid() = created_by);

create policy "team_owners_can_update"
  on teams for update
  using (
    auth.uid() = created_by or
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
      and team_members.role = 'owner'
    )
  );

create policy "team_owners_can_delete"
  on teams for delete
  using (auth.uid() = created_by);

-- Simplify project RLS policies
drop policy if exists "Users can view projects in teams they're members of" on projects;
drop policy if exists "Team members can create projects" on projects;
drop policy if exists "Team members can update projects in their team" on projects;
drop policy if exists "Team members can delete projects" on projects;

create policy "team_members_can_view_projects"
  on projects for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    ) or auth.uid() = created_by
  );

create policy "team_members_can_create_projects"
  on projects for insert
  with check (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

create policy "team_members_can_update_projects"
  on projects for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

create policy "team_members_can_delete_projects"
  on projects for delete
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

-- Simplify task RLS policies
drop policy if exists "Users can view tasks in projects they have access to" on tasks;
drop policy if exists "Team members can create tasks" on tasks;
drop policy if exists "Team members can update tasks" on tasks;
drop policy if exists "Team members can delete tasks" on tasks;

create policy "team_members_can_view_tasks"
  on tasks for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    ) or auth.uid() = created_by
  );

create policy "team_members_can_create_tasks"
  on tasks for insert
  with check (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );

create policy "team_members_can_update_tasks"
  on tasks for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );

create policy "team_members_can_delete_tasks"
  on tasks for delete
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );

-- Simplify team_members RLS - only team owners can manage members
drop policy if exists "Users can view team members for teams they're in" on team_members;
drop policy if exists "Team owners can add members" on team_members;
drop policy if exists "Team owners can update members" on team_members;
drop policy if exists "Team owners can remove members" on team_members;

-- Use security definer function for team member operations
-- Only authenticated users can see their own memberships
create policy "users_can_view_own_memberships"
  on team_members for select to authenticated
  using (user_id = auth.uid());

-- Only owners can add/update/remove members (enforced via function triggers)
create policy "owners_can_manage_members"
  on team_members for insert
  with check (
    auth.uid() in (
      select user_id from team_members tm
      where tm.team_id = team_members.team_id
      and tm.role = 'owner'
    )
  );

create policy "owners_can_update_members"
  on team_members for update
  using (
    auth.uid() in (
      select user_id from team_members tm
      where tm.team_id = team_members.team_id
      and tm.role = 'owner'
    )
  );

create policy "owners_can_delete_members"
  on team_members for delete
  using (
    auth.uid() in (
      select user_id from team_members tm
      where tm.team_id = team_members.team_id
      and tm.role = 'owner'
    )
  );
