create table public.profiles (id uuid primary key references auth.users, role text not null default 'user' check (role in ('user','admin')));
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select using (id = auth.uid());
create policy "edit own profile" on public.profiles for update using (id = auth.uid());
create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$ begin insert into public.profiles (id) values (new.id); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users default auth.uid(), body text not null);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
