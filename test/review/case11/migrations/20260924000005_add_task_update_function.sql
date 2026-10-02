-- Create a secure stored procedure for updating task status
-- This allows assignees to update task status without direct table access

create or replace function public.update_task_status(
  p_task_id uuid,
  p_new_status text
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_task_id uuid;
  v_project_id uuid;
  v_current_user uuid;
begin
  v_current_user := auth.uid();

  if v_current_user is null then
    raise exception 'Unauthorized';
  end if;

  -- Get the task and verify user has permission
  select t.id, t.project_id
  into v_task_id, v_project_id
  from tasks t
  where t.id = p_task_id
  and (
    t.created_by = v_current_user
    or t.assigned_to = v_current_user
    or exists (
      select 1 from projects p
      join team_members tm on tm.team_id = p.team_id
      where p.id = t.project_id
      and tm.user_id = v_current_user
      and tm.role in ('owner', 'admin')
    )
  );

  if v_task_id is null then
    raise exception 'Task not found or permission denied';
  end if;

  -- Update the task status
  update tasks
  set status = p_new_status, updated_at = now()
  where id = p_task_id;

  return json_build_object('success', true, 'task_id', p_task_id);
end;
$$;

grant execute on function public.update_task_status(uuid, text) to authenticated;

-- Now add trigger to prevent direct status updates via SQL
create or replace function public.vc_lock_tasks_money_status()
returns trigger
language plpgsql
as $$
begin
  if current_user in ('anon', 'authenticated') and not coalesce(false, false) then
    if new.status is distinct from old.status then
      raise exception 'permission denied: use update_task_status() function instead';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists vc_lock_tasks_money_status on public.tasks;
create trigger vc_lock_tasks_money_status
  before update on public.tasks
  for each row
  execute function public.vc_lock_tasks_money_status();
