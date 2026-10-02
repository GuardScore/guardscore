-- Create profiles table to store user roles
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text default 'user',
  created_at timestamp with time zone default now()
);

-- Enable RLS on profiles
alter table profiles enable row level security;

-- Users can read their own profile
create policy "Users can read own profile" on profiles
  for select
  using (auth.uid() = id);

-- Admins can read all profiles
create policy "Admins can read all profiles" on profiles
  for select
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.role = 'admin'
    )
  );

-- Trigger to auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'user');
  return new;
end;
$$;

-- Trigger for new user signup
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Update RLS on notes to allow admins to view all notes
create policy "Admins can read all notes" on notes
  for select
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.role = 'admin'
    )
  );

-- Admins can update any note (for moderation)
create policy "Admins can update any note" on notes
  for update
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.role = 'admin'
    )
  )
  with check (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.role = 'admin'
    )
  );

-- Admins can delete any note (for moderation)
create policy "Admins can delete any note" on notes
  for delete
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.role = 'admin'
    )
  );
