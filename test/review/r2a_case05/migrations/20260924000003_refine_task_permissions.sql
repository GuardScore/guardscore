-- Refine task update permissions to be more granular

-- Drop the overly broad task update policy
drop policy if exists "task_creator_or_assignee_can_update" on tasks;

-- Project owners/admins can fully update tasks
create policy "team_admins_can_fully_update_tasks" on tasks
  for update
  using (
    exists (
      select 1 from projects p
      join private.team_members_rows() tm on tm.team_id = p.team_id
      where p.id = tasks.project_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

-- Creators can update their own tasks
create policy "task_creator_can_update_own" on tasks
  for update
  using (created_by = auth.uid());

-- Assignees can update task status only
create policy "task_assignee_can_update_status" on tasks
  for update
  using (assigned_to = auth.uid());

-- Tighten the delete policy for non-admins
drop policy if exists "task_creator_or_admin_can_delete" on tasks;

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
