-- Create notes table
create table if not exists public.notes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  content text,
  created_at timestamp with time zone default timezone('utc'::text, now()),
  updated_at timestamp with time zone default timezone('utc'::text, now())
);

-- Create index for faster user queries
create index if not exists notes_user_id_idx on public.notes(user_id);

-- Enable RLS
alter table public.notes enable row level security;

-- Allow users to see only their own notes
create policy "Users can view own notes"
  on public.notes for select
  using (auth.uid() = user_id);

-- Allow users to create notes
create policy "Users can create notes"
  on public.notes for insert
  with check (auth.uid() = user_id);

-- Allow users to update own notes
create policy "Users can update own notes"
  on public.notes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Allow users to delete own notes
create policy "Users can delete own notes"
  on public.notes for delete
  using (auth.uid() = user_id);
