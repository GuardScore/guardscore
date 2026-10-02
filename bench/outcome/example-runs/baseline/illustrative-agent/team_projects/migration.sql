create table public.orgs (id uuid primary key, name text not null);
create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  org_id uuid not null references public.orgs(id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id),
  name text not null
);
alter table public.orgs enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;
create policy "members see org" on public.orgs for select to authenticated
  using (id in (select org_id from public.memberships where user_id = auth.uid()));
create policy "own memberships" on public.memberships for select to authenticated using (user_id = auth.uid());
-- Bug: users can create a membership for themselves in any org.
create policy "join" on public.memberships for insert to authenticated with check (user_id = auth.uid());
-- Bug: "logged in" is treated as "member of this org".
create policy "logged in" on public.projects for all to authenticated using (auth.uid() is not null);
