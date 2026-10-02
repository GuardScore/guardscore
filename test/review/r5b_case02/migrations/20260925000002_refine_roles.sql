-- Drop existing project policies
drop policy "projects_tenant_members" on projects;
drop policy "projects_insert_own" on projects;
drop policy "Project owners can update" on projects;
drop policy "Project owners can delete" on projects;

-- Refined project policies: only team owners can create/manage projects
create policy "Team members can view projects"
  on projects for select to authenticated
  using (team_id in (select team_id from private.team_members_rows() tm where tm.user_id = auth.uid()));

create policy "Team owners can create projects"
  on projects for insert to authenticated
  with check (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can update projects"
  on projects for update to authenticated
  using (
    exists (
      select 1 from teams
      where teams.id = projects.team_id
      and teams.owner_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from teams
      where teams.id = projects.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can delete projects"
  on projects for delete to authenticated
  using (
    exists (
      select 1 from teams
      where teams.id = projects.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Drop existing task update policy
drop policy "Users can update tasks they created or are assigned to" on tasks;

-- Refined task policies: members can update tasks they created or are assigned to
create policy "Members can update their tasks"
  on tasks for update to authenticated
  using (
    auth.uid() = created_by or
    auth.uid() = assignee_id
  )
  with check (
    auth.uid() = created_by or
    auth.uid() = assignee_id
  );

-- Team owners can update any task in their team's projects
create policy "Team owners can update all tasks"
  on tasks for update to authenticated
  using (
    exists (
      select 1 from projects
      join teams on teams.id = projects.team_id
      where projects.id = tasks.project_id
      and teams.owner_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from projects
      join teams on teams.id = projects.team_id
      where projects.id = tasks.project_id
      and teams.owner_id = auth.uid()
    )
  );
