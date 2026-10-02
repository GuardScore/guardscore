-- Fix RLS circular dependency causing users to not see tasks after joining
-- Problem: exists (select from team_members) in policies gets blocked by team_members RLS
-- Solution: Use security definer functions to check membership without RLS restrictions

-- Create security definer functions that bypass RLS for internal checks
create or replace function public.user_is_team_member(p_user_id uuid, p_team_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from team_members
    where team_members.user_id = p_user_id
    and team_members.team_id = p_team_id
  );
$$;

create or replace function public.user_is_team_owner(p_user_id uuid, p_team_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from team_members
    where team_members.user_id = p_user_id
    and team_members.team_id = p_team_id
    and team_members.role = 'owner'
  );
$$;

create or replace function public.user_is_project_member(p_user_id uuid, p_project_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from team_members
    where team_members.user_id = p_user_id
    and team_members.team_id = (
      select team_id from projects where id = p_project_id
    )
  );
$$;

-- Grant execute to authenticated users
grant execute on function public.user_is_team_member(uuid, uuid) to authenticated;
grant execute on function public.user_is_team_owner(uuid, uuid) to authenticated;
grant execute on function public.user_is_project_member(uuid, uuid) to authenticated;

-- Recreate team policies using security definer functions
drop policy if exists "users_can_view_their_teams" on teams;
drop policy if exists "team_owners_can_update" on teams;

create policy "users_can_view_their_teams"
  on teams for select
  using (
    auth.uid() = created_by or
    public.user_is_team_member(auth.uid(), id)
  );

create policy "team_owners_can_update"
  on teams for update
  using (
    auth.uid() = created_by or
    public.user_is_team_owner(auth.uid(), id)
  );

-- Recreate project policies using security definer functions
drop policy if exists "team_members_can_view_projects" on projects;
drop policy if exists "team_members_can_update_projects" on projects;

create policy "team_members_can_view_projects"
  on projects for select
  using (
    public.user_is_project_member(auth.uid(), id) or
    auth.uid() = created_by
  );

create policy "team_members_can_update_projects"
  on projects for update
  using (
    public.user_is_project_member(auth.uid(), projects.id)
  );

-- Recreate task policies using security definer functions
drop policy if exists "team_members_can_view_tasks" on tasks;
drop policy if exists "team_members_can_update_tasks" on tasks;

create policy "team_members_can_view_tasks"
  on tasks for select
  using (
    public.user_is_project_member(auth.uid(), project_id) or
    auth.uid() = created_by
  );

create policy "team_members_can_update_tasks"
  on tasks for update
  using (
    public.user_is_project_member(auth.uid(), project_id)
  );

-- Recreate team_members policies with proper read access for verification
drop policy if exists "users_can_view_own_memberships" on team_members;
drop policy if exists "owners_can_manage_members" on team_members;
drop policy if exists "owners_can_update_members" on team_members;
drop policy if exists "owners_can_delete_members" on team_members;

-- Allow users to see all team members if they're in the team
create policy "team_members_can_view_team_members"
  on team_members for select
  using (
    public.user_is_team_member(auth.uid(), team_id)
  );

-- Only owners can add members
create policy "owners_can_add_members"
  on team_members for insert
  with check (
    public.user_is_team_owner(auth.uid(), team_id)
  );

-- Only owners can update member roles
create policy "owners_can_update_members"
  on team_members for update
  using (
    public.user_is_team_owner(auth.uid(), team_id)
  );

-- Only owners can remove members
create policy "owners_can_remove_members"
  on team_members for delete
  using (
    public.user_is_team_owner(auth.uid(), team_id)
  );

-- Update invitations policies to use security definer functions
drop policy if exists "team_owners_can_view_invitations" on invitations;
drop policy if exists "team_owners_can_create_invitations" on invitations;
drop policy if exists "team_owners_can_update_invitations" on invitations;

create policy "team_owners_can_view_invitations"
  on invitations for select
  using (
    public.user_is_team_owner(auth.uid(), team_id)
  );

create policy "team_owners_can_create_invitations"
  on invitations for insert
  with check (
    auth.uid() = invited_by and
    public.user_is_team_owner(auth.uid(), team_id)
  );

create policy "team_owners_can_update_invitations"
  on invitations for update
  using (
    public.user_is_team_owner(auth.uid(), team_id)
  );
