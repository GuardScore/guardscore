create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
create policy "notes_select_own" on public.notes for select to authenticated using (user_id = auth.uid());
create policy "notes_insert_own" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "notes_update_own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "notes_delete_own" on public.notes for delete to authenticated using (user_id = auth.uid());

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
create policy "members only" on public.projects for all to authenticated
  using (org_id in (select org_id from public.memberships where user_id = auth.uid()))
  with check (org_id in (select org_id from public.memberships where user_id = auth.uid()));

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
create policy "owner only" on storage.objects for all to authenticated using (owner = auth.uid()) with check (owner = auth.uid());
