-- Create journal_entries table
create table journal_entries (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users on delete cascade,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index for faster queries by user
create index idx_journal_entries_user_id on journal_entries(user_id);
create index idx_journal_entries_created_at on journal_entries(created_at);

-- Enable RLS
alter table journal_entries enable row level security;

-- Users can only see their own entries
create policy "Users can view their own entries"
  on journal_entries for select
  using (auth.uid() = user_id);

-- Users can create entries
create policy "Users can create entries"
  on journal_entries for insert
  with check (auth.uid() = user_id);

-- Users can update their own entries
create policy "Users can update their own entries"
  on journal_entries for update
  using (auth.uid() = user_id);

-- Users can delete their own entries
create policy "Users can delete their own entries"
  on journal_entries for delete
  using (auth.uid() = user_id);
