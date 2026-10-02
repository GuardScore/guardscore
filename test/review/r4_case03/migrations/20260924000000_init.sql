-- Create journal_entries table
create table journal_entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index for faster queries
create index journal_entries_user_id_idx on journal_entries(user_id);
create index journal_entries_created_at_idx on journal_entries(created_at);

-- Enable RLS
alter table journal_entries enable row level security;

-- RLS policies - users can only view their own entries
create policy "Users can view their own journal entries" on journal_entries
  for select using (auth.uid() = user_id);

-- Users can insert their own entries
create policy "Users can insert their own journal entries" on journal_entries
  for insert with check (auth.uid() = user_id);

-- Users can update their own entries
create policy "Users can update their own journal entries" on journal_entries
  for update using (auth.uid() = user_id);

-- Users can delete their own entries
create policy "Users can delete their own journal entries" on journal_entries
  for delete using (auth.uid() = user_id);
