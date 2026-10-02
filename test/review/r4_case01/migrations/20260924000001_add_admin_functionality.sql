-- Create profiles table to track admin status
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  is_admin boolean not null default false,
  created_at timestamp with time zone not null default now()
);

-- Enable RLS on profiles
alter table profiles enable row level security;

-- Users can read their own profile
create policy "Users can read their own profile" on profiles
  for select
  using (auth.uid() = id);

-- Admins can read all profiles
create policy "Admins can read all profiles" on profiles
  for select
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.is_admin = true
    )
  );

-- Update RLS on notes table to allow admins to read all notes
create policy "Admins can read all notes" on notes
  for select
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
      and profiles.is_admin = true
    )
  );

-- Create trigger to automatically create a profile when a user signs up
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, is_admin)
  values (new.id, new.email, false);
  return new;
end;
$$ language plpgsql security definer;

-- Trigger the function every time a user is created
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
