-- Create profiles table to track admin status
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  is_admin boolean default false,
  created_at timestamp with time zone default timezone('utc'::text, now())
);

-- Create index for admin queries
create index if not exists profiles_is_admin_idx on public.profiles(is_admin);

-- Enable RLS
alter table public.profiles enable row level security;

-- Allow users to view their own profile
create policy "Users can view own profile"
  on public.profiles for select
  using (auth.uid() = id);

-- Allow admins to view all profiles
create policy "Admins can view all profiles"
  on public.profiles for select
  using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and is_admin = true
    )
  );

-- Update notes RLS to allow admins to see all notes
drop policy if exists "Users can view own notes" on public.notes;

create policy "Users can view own notes"
  on public.notes for select
  using (auth.uid() = user_id);

create policy "Admins can view all notes"
  on public.notes for select
  using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and is_admin = true
    )
  );

-- Allow admins to delete any note
create policy "Admins can delete any note"
  on public.notes for delete
  using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and is_admin = true
    )
  );

-- Create function to set first user as admin
create or replace function public.set_first_user_as_admin()
returns void as $$
declare
  user_count int;
begin
  select count(*) into user_count from public.profiles;

  if user_count = 0 then
    insert into public.profiles (id, is_admin)
    select id, true from auth.users limit 1;
  end if;
end;
$$ language plpgsql security definer;

-- Create trigger to auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, is_admin)
  values (new.id, new.email, false);

  -- Make the first user an admin
  if (select count(*) from public.profiles) = 1 then
    update public.profiles set is_admin = true where id = new.id;
  end if;

  return new;
end;
$$ language plpgsql security definer;

-- Drop trigger if it exists
drop trigger if exists on_auth_user_created on auth.users;

-- Create trigger for new user
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
