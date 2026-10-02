-- Enable required extensions
create extension if not exists "uuid-ossp";

-- Notes table
create table if not exists notes (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  content text not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Indexes for better query performance
create index if not exists idx_notes_user_id on notes(user_id);
create index if not exists idx_notes_created_at on notes(created_at desc);

-- Enable RLS (Row Level Security)
alter table notes enable row level security;

-- RLS Policy: Users can only see their own notes
create policy "Users can view their own notes"
  on notes for select
  using (auth.uid() = user_id);

-- RLS Policy: Users can insert notes for themselves
create policy "Users can insert their own notes"
  on notes for insert
  with check (auth.uid() = user_id);

-- RLS Policy: Users can update their own notes
create policy "Users can update their own notes"
  on notes for update
  using (auth.uid() = user_id);

-- RLS Policy: Users can delete their own notes
create policy "Users can delete their own notes"
  on notes for delete
  using (auth.uid() = user_id);
