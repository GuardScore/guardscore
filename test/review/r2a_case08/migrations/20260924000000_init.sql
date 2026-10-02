-- Create profiles table
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create entries table
create table if not exists entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  title text,
  content text not null,
  mood_rating integer not null check (mood_rating >= 1 and mood_rating <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  created_date date default current_date
);

-- Create indexes for better query performance
create index if not exists entries_user_id_idx on entries(user_id);
create index if not exists entries_created_date_idx on entries(created_date);
create index if not exists entries_user_created_date_idx on entries(user_id, created_date);

-- Enable RLS
alter table profiles enable row level security;
alter table entries enable row level security;

-- RLS policies for profiles
create policy "Users can view their own profile" on profiles
  for select using (auth.uid() = id);

create policy "Users can update their own profile" on profiles
  for update using (auth.uid() = id);

-- RLS policies for entries
create policy "Users can view their own entries" on entries
  for select using (auth.uid() = user_id);

create policy "Users can create entries" on entries
  for insert with check (auth.uid() = user_id);

create policy "Users can update their own entries" on entries
  for update using (auth.uid() = user_id);

create policy "Users can delete their own entries" on entries
  for delete using (auth.uid() = user_id);
