-- The secure version of 10 + 12, with no seed and no manifest hints:
-- teams/projects/tasks scoped by membership, profile roles locked by a trigger,
-- a share-links table that grants access on purpose.
create extension if not exists "uuid-ossp";
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'user' check (role in ('user', 'admin')),
  is_private boolean not null default false
);
alter table public.profiles enable row level security;
create policy "read own" on public.profiles for select to authenticated using (id = (select auth.uid()));
create policy "update own" on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));
create or replace function public.protect_role() returns trigger language plpgsql as $$
begin
  if new.role is distinct from old.role and not public.is_admin() then
    raise exception 'Only admins can change roles';
  end if;
  return new;
end $$;
create trigger protect_role before update on public.profiles for each row execute function public.protect_role();
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create table public.teams (id uuid primary key default uuid_generate_v4(), name text not null, created_by uuid references auth.users default auth.uid());
create table public.team_members (
  team_id uuid not null references public.teams on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  primary key (team_id, user_id)
);
create table public.projects (id bigint generated always as identity primary key, team_id uuid not null references public.teams, name text not null);
create table public.tasks (id uuid primary key default gen_random_uuid(), project_id bigint not null references public.projects on delete cascade, title text not null, status text not null check (status in ('todo', 'doing', 'done')));
create table public.task_share_links (token text primary key, task_id uuid not null references public.tasks);
alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.projects enable row level security;
alter table public.tasks enable row level security;
alter table public.task_share_links enable row level security;

create or replace function public.is_member(t uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.team_members where team_id = t and user_id = auth.uid());
$$;
create policy "members read" on public.teams for select to authenticated using (public.is_member(id) or created_by = auth.uid());
create policy "members update" on public.teams for update to authenticated using (public.is_member(id)) with check (public.is_member(id));
create policy "create own team" on public.teams for insert to authenticated with check (created_by = auth.uid());
create policy "own memberships" on public.team_members for select to authenticated using (user_id = auth.uid());
create policy "members projects" on public.projects for all to authenticated using (public.is_member(team_id)) with check (public.is_member(team_id));
create policy "members tasks" on public.tasks for all to authenticated
  using (exists (select 1 from public.projects p where p.id = project_id))
  with check (exists (select 1 from public.projects p where p.id = project_id));
create policy "members links" on public.task_share_links for all to authenticated
  using (exists (select 1 from public.tasks t where t.id = task_id)) with check (exists (select 1 from public.tasks t where t.id = task_id));

-- Adds the creator as owner when a team is made.
create or replace function public.add_creator() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.team_members (team_id, user_id, role) values (new.id, auth.uid(), 'owner'); return new; end $$;
create trigger add_creator after insert on public.teams for each row execute function public.add_creator();
