-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Entries table
create table entries (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  date date not null default current_date,
  unique(user_id, date)
);

-- Indexes for faster queries
create index idx_entries_user_id on entries(user_id);
create index idx_entries_date on entries(date desc);
create index idx_entries_user_date on entries(user_id, date desc);

-- RLS (Row Level Security)
alter table entries enable row level security;

create policy "Users can view their own entries"
  on entries for select
  using (auth.uid() = user_id);

create policy "Users can create their own entries"
  on entries for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own entries"
  on entries for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own entries"
  on entries for delete
  using (auth.uid() = user_id);
