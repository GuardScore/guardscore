-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Create users table (Supabase auth.users is managed by auth service)
-- But we'll create a public users profile table
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text unique not null,
  created_at timestamp with time zone default now()
);

-- Create notes table
create table public.notes (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users on delete cascade,
  title text not null,
  content text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable row level security
alter table public.profiles enable row level security;
alter table public.notes enable row level security;

-- Profiles RLS policies
create policy "Users can view their own profile"
  on public.profiles
  for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles
  for update
  using (auth.uid() = id);

-- Notes RLS policies
create policy "Users can view their own notes"
  on public.notes
  for select
  using (auth.uid() = user_id);

create policy "Users can insert their own notes"
  on public.notes
  for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own notes"
  on public.notes
  for update
  using (auth.uid() = user_id);

create policy "Users can delete their own notes"
  on public.notes
  for delete
  using (auth.uid() = user_id);

-- Create indexes for performance
create index notes_user_id_idx on public.notes(user_id);
create index notes_created_at_idx on public.notes(created_at desc);
