-- Members may edit their own membership (notification settings); nothing
-- stops them changing their own role to owner.
create table public.teams (id uuid primary key default gen_random_uuid(), name text not null);
create table public.team_members (
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  notify boolean not null default true,
  primary key (team_id, user_id)
);
create or replace function public.is_member(t uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.team_members where team_id = t and user_id = auth.uid());
$$;
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
create policy "members read team" on public.teams for select to authenticated using (public.is_member(id));
create policy "members see team members" on public.team_members for select to authenticated using (public.is_member(team_id));
create policy "edit own membership" on public.team_members for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
