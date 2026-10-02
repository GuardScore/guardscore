-- Create notes table
create table if not exists notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  content text not null default '',
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table notes enable row level security;

-- RLS policies: users can only see/edit their own notes
create policy "Users can view their own notes"
  on notes for select
  using (auth.uid() = user_id);

create policy "Users can insert their own notes"
  on notes for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own notes"
  on notes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own notes"
  on notes for delete
  using (auth.uid() = user_id);

-- Create index for faster queries
create index idx_notes_user_id on notes(user_id);
