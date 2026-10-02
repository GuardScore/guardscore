-- Drop existing policies and replace with clearer role-based ones

-- Teams policies (no changes needed - owner controls everything)

-- Projects: Only owner/admin can create/update/delete; all members can view
drop policy if exists "Team members can create projects" on projects;
drop policy if exists "Team members can update projects" on projects;

create policy "Only owner/admin can create projects"
  on projects for insert
  with check (
    exists (
      select 1 from team_members
      where team_id = projects.team_id
      and user_id = auth.uid()
      and role in ('owner', 'admin')
    )
  );

create policy "Only owner/admin can update projects"
  on projects for update
  using (
    exists (
      select 1 from team_members
      where team_id = projects.team_id
      and user_id = auth.uid()
      and role in ('owner', 'admin')
    )
  );

-- Tasks: Only owner/admin can delete; all members can create/update
drop policy if exists "Team members can create tasks" on tasks;
drop policy if exists "Team members can update tasks" on tasks;
drop policy if exists "Team owner can delete tasks" on tasks;

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams
        where owner_id = auth.uid()
        or id in (select team_id from team_members where user_id = auth.uid())
      )
    )
  );

create policy "Team members can update their tasks"
  on tasks for update
  using (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams
        where owner_id = auth.uid()
        or id in (select team_id from team_members where user_id = auth.uid())
      )
    )
  );

create policy "Only owner can delete tasks"
  on tasks for delete
  using (
    exists (
      select 1 from projects
      inner join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
      and team_members.role = 'owner'
    )
  );

-- Team members: Add/remove only by owner/admin
drop policy if exists "Team owner and admins can manage team members" on team_members;
drop policy if exists "Team owner and admins can remove team members" on team_members;

create policy "Only owner can add team members"
  on team_members for insert
  with check (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
  );

create policy "Only owner can remove team members"
  on team_members for delete
  using (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
  );

create policy "Only owner can update member roles"
  on team_members for update
  using (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
  );
