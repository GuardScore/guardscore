-- Update RLS policies to enforce role-based permissions

-- Drop existing project policies
drop policy if exists "team_members_can_read_projects" on projects;
drop policy if exists "team_members_can_create_projects" on projects;
drop policy if exists "team_members_can_update_projects" on projects;

-- Projects: viewable by team members, creatable/updatable by owners/admins
create policy "team_members_can_read_projects" on projects
  for select
  using (
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = projects.team_id
      and tm.user_id = auth.uid()
    )
  );

create policy "team_owners_admins_can_create_projects" on projects
  for insert
  with check (
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = projects.team_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

create policy "team_owners_admins_can_update_projects" on projects
  for update
  using (
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = projects.team_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

-- Drop existing task policies
drop policy if exists "team_members_can_read_tasks" on tasks;
drop policy if exists "team_members_can_create_tasks" on tasks;
drop policy if exists "team_members_can_update_tasks" on tasks;

-- Tasks: viewable by team members, creatable by all team members, updatable by creator or assignee
create policy "team_members_can_read_tasks" on tasks
  for select
  using (
    exists (
      select 1 from projects p
      join private.team_members_rows() tm on tm.team_id = p.team_id
      where p.id = tasks.project_id
      and tm.user_id = auth.uid()
    )
  );

create policy "team_members_can_create_tasks" on tasks
  for insert
  with check (
    exists (
      select 1 from projects p
      join private.team_members_rows() tm on tm.team_id = p.team_id
      where p.id = tasks.project_id
      and tm.user_id = auth.uid()
    )
  );

create policy "task_creator_or_assignee_can_update" on tasks
  for update
  using (
    created_by = auth.uid()
    or assigned_to = auth.uid()
    or exists (
      select 1 from projects p
      join private.team_members_rows() tm on tm.team_id = p.team_id
      where p.id = tasks.project_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

create policy "task_creator_or_admin_can_delete" on tasks
  for delete
  using (
    created_by = auth.uid()
    or exists (
      select 1 from projects p
      join private.team_members_rows() tm on tm.team_id = p.team_id
      where p.id = tasks.project_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

-- Team members: only owners can manage
drop policy if exists "team_owners_can_manage" on team_members;
drop policy if exists "team_owners_can_remove" on team_members;

create policy "team_owners_can_manage_members" on team_members
  for insert
  with check (
    exists (
      select 1 from teams
      where teams.id = team_members.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "team_owners_can_update_members" on team_members
  for update
  using (
    exists (
      select 1 from teams
      where teams.id = team_members.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "team_owners_can_remove_members" on team_members
  for delete
  using (
    exists (
      select 1 from teams
      where teams.id = team_members.team_id
      and teams.owner_id = auth.uid()
    )
  );
