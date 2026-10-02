-- Agent-style team tool with invitations, intended secure.
create table public.teams (id uuid primary key default gen_random_uuid(), name text not null, owner_id uuid not null references auth.users default auth.uid(), created_at timestamptz default now());
create table public.team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  unique (team_id, user_id)
);
create table public.team_invitations (
  id uuid primary key default gen_random_uuid(), team_id uuid not null references public.teams on delete cascade,
  email text not null, token uuid not null default gen_random_uuid(), invited_by uuid references auth.users, accepted_at timestamptz
);
create table public.projects (id uuid primary key default gen_random_uuid(), team_id uuid not null references public.teams on delete cascade, name text not null, description text);
create table public.tasks (
  id uuid primary key default gen_random_uuid(), project_id uuid not null references public.projects on delete cascade,
  title text not null, status text not null default 'todo' check (status in ('todo', 'in_progress', 'done')),
  assignee_id uuid references auth.users, due_date date, created_by uuid references auth.users default auth.uid()
);
create or replace function public.is_team_member(tid uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members where team_id = tid and user_id = auth.uid()); $$;
create or replace function public.is_team_owner(tid uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from team_members where team_id = tid and user_id = auth.uid() and role = 'owner'); $$;
create or replace function public.handle_new_team() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into team_members (team_id, user_id, role) values (new.id, new.owner_id, 'owner'); return new; end $$;
create trigger on_team_created after insert on public.teams for each row execute function public.handle_new_team();
create or replace function public.accept_invitation(invite_token uuid) returns void language plpgsql security definer set search_path = public as $$
declare inv team_invitations;
begin
  select * into inv from team_invitations where token = invite_token and accepted_at is null
    and lower(email) = lower((select email from auth.users where id = auth.uid()));
  if inv.id is null then raise exception 'Invalid invitation'; end if;
  insert into team_members (team_id, user_id) values (inv.team_id, auth.uid()) on conflict do nothing;
  update team_invitations set accepted_at = now() where id = inv.id;
end $$;
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.team_invitations enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;
create policy "view teams" on public.teams for select to authenticated using (public.is_team_member(id));
create policy "create teams" on public.teams for insert to authenticated with check (owner_id = auth.uid());
create policy "owners update teams" on public.teams for update to authenticated using (public.is_team_owner(id));
create policy "owners delete teams" on public.teams for delete to authenticated using (public.is_team_owner(id));
create policy "view members" on public.team_members for select to authenticated using (public.is_team_member(team_id));
create policy "owners manage members" on public.team_members for delete to authenticated using (public.is_team_owner(team_id));
create policy "owners update members" on public.team_members for update to authenticated using (public.is_team_owner(team_id)) with check (public.is_team_owner(team_id));
create policy "owners invite" on public.team_invitations for all to authenticated using (public.is_team_owner(team_id)) with check (public.is_team_owner(team_id));
create policy "members projects" on public.projects for all to authenticated using (public.is_team_member(team_id)) with check (public.is_team_member(team_id));
create policy "members tasks" on public.tasks for all to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id and public.is_team_member(p.team_id)))
  with check (exists (select 1 from public.projects p where p.id = project_id and public.is_team_member(p.team_id)));
