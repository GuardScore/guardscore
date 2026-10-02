-- Create notes table
create table if not exists notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  content text default '',
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index on user_id for faster queries
create index if not exists idx_notes_user_id on notes(user_id);

-- Enable RLS
alter table notes enable row level security;

-- Users can read their own notes
create policy "Users can read own notes" on notes
  for select
  using (auth.uid() = user_id);

-- Users can create notes
create policy "Users can create notes" on notes
  for insert
  with check (auth.uid() = user_id);

-- Users can update their own notes
create policy "Users can update own notes" on notes
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Users can delete their own notes
create policy "Users can delete own notes" on notes
  for delete
  using (auth.uid() = user_id);
