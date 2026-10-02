-- Drop all policies that might have recursion issues
drop policy if exists "Users can view their teams" on teams;
drop policy if exists "Users can view team members of their teams" on team_members;
drop policy if exists "Users can view team members in their teams" on team_members;
drop policy if exists "Users can view projects in their teams" on projects;
drop policy if exists "Users can view tasks in their projects" on tasks;
drop policy if exists "Users can view tasks in their team projects" on tasks;
drop policy if exists "Team members can create projects" on projects;
drop policy if exists "Team members can update projects in their teams" on projects;
drop policy if exists "Team members can update projects" on projects;
drop policy if exists "Users can create tasks" on tasks;
drop policy if exists "Team members can create tasks" on tasks;
drop policy if exists "Users can update tasks they created or are assigned to" on tasks;
drop policy if exists "Users can update their own tasks or assigned tasks" on tasks;

-- Recreate all select policies using private schema function to avoid recursion
create policy "Users can view their teams"
  on teams for select
  using (
    id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid()
    )
  );

create policy "Users can view team members in their teams"
  on team_members for select
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid()
    )
  );

create policy "Users can view projects in their teams"
  on projects for select
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid()
    )
  );

create policy "Users can view tasks in their team projects"
  on tasks for select
  using (
    project_id in (
      select p.id from projects p
      where p.team_id in (
        select team_id from private.team_members_rows()
        where user_id = auth.uid()
      )
    )
  );

-- Recreate create/update policies
create policy "Team members can create projects"
  on projects for insert
  with check (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid()
    )
  );

create policy "Team members can update projects"
  on projects for update
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid()
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    project_id in (
      select p.id from projects p
      where p.team_id in (
        select team_id from private.team_members_rows()
        where user_id = auth.uid()
      )
    )
  );

create policy "Users can update their own tasks or assigned tasks"
  on tasks for update
  using (
    created_by = auth.uid()
    or assigned_to = auth.uid()
    or project_id in (
      select p.id from projects p
      where p.team_id in (
        select team_id from private.team_members_rows()
        where user_id = auth.uid() and role = 'owner'
      )
    )
  );
