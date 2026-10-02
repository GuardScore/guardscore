-- Create users table (extends Supabase auth)
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  created_at timestamp with time zone default now()
);

-- Create notes table
create table if not exists notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  title text not null,
  content text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS
alter table profiles enable row level security;
alter table notes enable row level security;

-- RLS policies for profiles
create policy "Users can read their own profile"
  on profiles for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on profiles for update
  using (auth.uid() = id);

-- RLS policies for notes
create policy "Users can read their own notes"
  on notes for select
  using (auth.uid() = user_id);

create policy "Users can create notes"
  on notes for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own notes"
  on notes for update
  using (auth.uid() = user_id);

create policy "Users can delete their own notes"
  on notes for delete
  using (auth.uid() = user_id);

-- Create index for faster queries
create index if not exists notes_user_id_idx on notes(user_id);
