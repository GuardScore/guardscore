-- Create admin_users table to track which users are admins
create table public.admin_users (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create index for faster lookups
create index idx_admin_users_user_id on public.admin_users(user_id);

-- Enable RLS
alter table public.admin_users enable row level security;

-- Admins can view admin table
create policy "Admins can view admin table"
  on public.admin_users for select
  using (
    auth.uid() in (
      select user_id from public.admin_users
    )
  );

-- Add policy for admins to view all notes
create policy "Admins can view all notes"
  on public.notes for select
  using (
    auth.uid() in (
      select user_id from public.admin_users
    )
  );

-- Add policy for admins to delete any note
create policy "Admins can delete any note"
  on public.notes for delete
  using (
    auth.uid() in (
      select user_id from public.admin_users
    )
  );
