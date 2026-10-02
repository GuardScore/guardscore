-- Trigger to prevent users from changing project status
-- Only the server/admin API can change project status
create or replace function public.vc_lock_projects_money_status()
returns trigger
language plpgsql
as $$
begin
  if current_user in ('anon', 'authenticated') and not coalesce(false, false) then
    if new.status is distinct from old.status then
      raise exception 'permission denied: only staff can change status';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists vc_lock_projects_money_status on public.projects;
create trigger vc_lock_projects_money_status
  before update on public.projects
  for each row
  execute function public.vc_lock_projects_money_status();

-- Note: Project status is now immutable by all authenticated users
-- To change project status, use server-side functions or Supabase admin API
