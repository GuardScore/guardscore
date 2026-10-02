-- Create notes table
create table notes (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null references auth.users on delete cascade,
  title text not null,
  content text default '',
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index on user_id for faster queries
create index notes_user_id_idx on notes(user_id);

-- Enable RLS
alter table notes enable row level security;

-- Policy: Users can only read their own notes
create policy "Users can read their own notes"
  on notes for select
  using (auth.uid() = user_id);

-- Policy: Users can only insert their own notes
create policy "Users can insert their own notes"
  on notes for insert
  with check (auth.uid() = user_id);

-- Policy: Users can only update their own notes
create policy "Users can update their own notes"
  on notes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy: Users can only delete their own notes
create policy "Users can delete their own notes"
  on notes for delete
  using (auth.uid() = user_id);
