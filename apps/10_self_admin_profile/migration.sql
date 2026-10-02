-- Profiles carry a role; an admin check reads it; users may edit their own profile.
-- Nothing stops a user from setting their own role to 'admin'.
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  display_name text,
  role text not null default 'user' check (role in ('user', 'admin'))
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select to authenticated using (id = auth.uid());
create policy "update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name) values (new.id, split_part(new.email, '@', 1));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create or replace function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text not null
);
alter table public.notes enable row level security;
create policy "own notes or admin" on public.notes for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "insert own" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "update own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "delete own" on public.notes for delete to authenticated using (user_id = auth.uid());
