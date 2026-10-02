-- Update team_members role constraint to only owner and member
alter table team_members drop constraint team_members_role_check;
alter table team_members add constraint team_members_role_check check (role in ('owner', 'member'));

-- Update role default to member
alter table team_members alter column role set default 'member';

-- Drop and recreate team management policies to restrict to owners only
drop policy if exists "Admins can add team members" on team_members;
drop policy if exists "Admins can update team members" on team_members;
drop policy if exists "Admins can remove team members" on team_members;
drop policy if exists "Admins can delete projects" on projects;
drop policy if exists "Admins can delete tasks" on tasks;

-- Only owners can manage team members (using private schema to avoid recursion)
create policy "Owners can add team members"
  on team_members for insert
  with check (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

create policy "Owners can update team members"
  on team_members for update
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

create policy "Owners can remove team members"
  on team_members for delete
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

-- Only team owners can delete projects
create policy "Owners can delete projects"
  on projects for delete
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

-- Only team owners can delete tasks
create policy "Owners can delete tasks"
  on tasks for delete
  using (
    project_id in (
      select id from projects
      where team_id in (
        select team_id from private.team_members_rows()
        where user_id = auth.uid() and role = 'owner'
      )
    )
  );

-- Update trigger to add creator as owner instead of admin
create or replace function public."zz_vc_add_creator_to_team_members"() returns trigger language plpgsql security definer set search_path = public as $trg$
begin
  if auth.uid() is not null and not exists (select 1 from public."team_members" where "user_id" = auth.uid() and "team_id" = new."id") then
    insert into public."team_members" ("user_id", "team_id", "role") values (auth.uid(), new."id", 'owner');
  end if;
  return new;
end $trg$;
drop trigger if exists "zz_vc_add_creator_to_team_members" on public."teams";
create trigger "zz_vc_add_creator_to_team_members" after insert on public."teams" for each row execute function public."zz_vc_add_creator_to_team_members"();
