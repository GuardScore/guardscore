-- Admin users table
create table if not exists admin_users (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on admin_users (only service role can view/modify)
alter table admin_users enable row level security;

create policy "Disable direct admin_users access"
  on admin_users for all
  using (false);

-- Update notes RLS policies to allow admins to view all notes
drop policy "Users can view their own notes" on notes;

create policy "Users can view their own notes, admins can view all"
  on notes for select
  using (
    auth.uid() = user_id
    or exists (select 1 from admin_users where admin_users.user_id = auth.uid())
  );

-- Allow admins to delete any note
drop policy "Users can delete their own notes" on notes;

create policy "Users can delete their own notes, admins can delete any"
  on notes for delete
  using (
    auth.uid() = user_id
    or exists (select 1 from admin_users where admin_users.user_id = auth.uid())
  );

-- Helper function to check if user is admin
create or replace function is_admin(user_id uuid)
returns boolean as $$
  select exists(select 1 from admin_users where admin_users.user_id = $1)
$$ language sql security definer;
