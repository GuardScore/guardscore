-- Teams -> projects -> tasks, no seed and no manifest hints. Projects are
-- correctly scoped to team members; tasks check only that you're logged in.
create table public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
create table public.team_members (
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  primary key (team_id, user_id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams on delete cascade,
  name text not null
);
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects on delete cascade,
  title text not null,
  done boolean not null default false
);
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;

create or replace function public.is_member(t uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.team_members where team_id = t and user_id = auth.uid());
$$;
create policy "members read team" on public.teams for select to authenticated using (public.is_member(id));
create policy "members update team" on public.teams for update to authenticated using (public.is_member(id)) with check (public.is_member(id));
create policy "anyone creates a team" on public.teams for insert to authenticated with check (true);
create policy "see own memberships" on public.team_members for select to authenticated using (user_id = auth.uid());
create policy "members use projects" on public.projects for all to authenticated using (public.is_member(team_id)) with check (public.is_member(team_id));
create policy "logged in users use tasks" on public.tasks for all to authenticated using (true) with check (true);
