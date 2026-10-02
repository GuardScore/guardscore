-- Create journal_entries table
create table journal_entries (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  mood_rating integer not null check (mood_rating >= 1 and mood_rating <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index for faster queries by user
create index idx_journal_entries_user_id on journal_entries(user_id);
create index idx_journal_entries_created_at on journal_entries(created_at);

-- Enable RLS
alter table journal_entries enable row level security;

-- RLS Policy: Users can only read their own entries
create policy "Users can read own entries"
  on journal_entries
  for select
  using (auth.uid() = user_id);

-- RLS Policy: Users can only insert their own entries
create policy "Users can insert own entries"
  on journal_entries
  for insert
  with check (auth.uid() = user_id);

-- RLS Policy: Users can only update their own entries
create policy "Users can update own entries"
  on journal_entries
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- RLS Policy: Users can only delete their own entries
create policy "Users can delete own entries"
  on journal_entries
  for delete
  using (auth.uid() = user_id);

-- Create a function to update updated_at
create or replace function update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

-- Create trigger for updated_at
create trigger update_journal_entries_updated_at
before update on journal_entries
for each row
execute function update_updated_at_column();
