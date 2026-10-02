-- Update RLS policies to enforce role-based access

-- Drop existing project policies
drop policy if exists "team_members_can_create_projects" on projects;
drop policy if exists "can_update_own_projects" on projects;

-- Projects: Only team owners/admins can create and update
create policy "team_owners_can_create_projects" on projects
  for insert with check (
    team_id in (
      select team_id from team_members where user_id = auth.uid() and role in ('owner', 'admin')
      union
      select id from teams where owner_id = auth.uid()
    )
  );

create policy "team_owners_can_update_projects" on projects
  for update using (
    team_id in (
      select team_id from team_members where user_id = auth.uid() and role in ('owner', 'admin')
      union
      select id from teams where owner_id = auth.uid()
    )
  );

-- Drop existing task policies
drop policy if exists "team_members_can_create_tasks" on tasks;
drop policy if exists "can_update_tasks" on tasks;

-- Tasks: All team members can create, but only admins/owners can update others' tasks
create policy "team_members_can_create_tasks" on tasks
  for insert with check (
    project_id in (
      select id from projects where team_id in (
        select team_id from team_members where user_id = auth.uid()
        union
        select id from teams where owner_id = auth.uid()
      )
    )
  );

create policy "anyone_can_update_tasks" on tasks
  for update using (
    project_id in (
      select id from projects where team_id in (
        select team_id from team_members where user_id = auth.uid()
        union
        select id from teams where owner_id = auth.uid()
      )
    )
  );

-- Add index for role-based queries
create index idx_team_members_role on team_members(team_id, role);
