-- Create journal_entries table
create table if not exists public.journal_entries (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create an index on user_id and created_at for efficient queries
create index if not exists idx_journal_entries_user_created
  on public.journal_entries(user_id, created_at desc);

-- Enable RLS
alter table public.journal_entries enable row level security;

-- Policies: Users can only access their own entries
do $$
begin
  if not exists (
    select 1 from pg_policies
    where tablename = 'journal_entries' and policyname = 'users_can_view_own_entries'
  ) then
    create policy "users_can_view_own_entries"
      on public.journal_entries
      for select
      using (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where tablename = 'journal_entries' and policyname = 'users_can_insert_own_entries'
  ) then
    create policy "users_can_insert_own_entries"
      on public.journal_entries
      for insert
      with check (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where tablename = 'journal_entries' and policyname = 'users_can_update_own_entries'
  ) then
    create policy "users_can_update_own_entries"
      on public.journal_entries
      for update
      using (auth.uid() = user_id)
      with check (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where tablename = 'journal_entries' and policyname = 'users_can_delete_own_entries'
  ) then
    create policy "users_can_delete_own_entries"
      on public.journal_entries
      for delete
      using (auth.uid() = user_id);
  end if;
end $$;
