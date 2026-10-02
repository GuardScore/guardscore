-- Create admin_users table to track who is an admin
create table if not exists admin_users (
  id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamp with time zone not null default now()
);

-- Enable RLS on admin_users
alter table admin_users enable row level security;

-- Only admins can view admin table
create policy "Admins can view admin users"
  on admin_users for select
  using (exists(select 1 from admin_users where id = auth.uid()));

-- Modify notes RLS to allow admins to see all notes
create policy "Admins can view all notes"
  on notes for select
  using (exists(select 1 from admin_users where id = auth.uid()));

-- Admins can delete any note
create policy "Admins can delete any note"
  on notes for delete
  using (exists(select 1 from admin_users where id = auth.uid()));

-- Create a function to check if user is admin
create or replace function is_admin(user_id uuid)
returns boolean as $$
  select exists(select 1 from admin_users where id = user_id);
$$ language sql security definer;

-- Create an audit log table for moderation actions
create table if not exists moderation_logs (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null references auth.users(id) on delete cascade,
  action text not null,
  note_id uuid references notes(id) on delete set null,
  user_id uuid references auth.users(id) on delete set null,
  details text,
  created_at timestamp with time zone not null default now()
);

-- Enable RLS on moderation_logs
alter table moderation_logs enable row level security;

-- Only admins can view moderation logs
create policy "Admins can view moderation logs"
  on moderation_logs for select
  using (exists(select 1 from admin_users where id = auth.uid()));

-- Only admins can insert moderation logs
create policy "Admins can create moderation logs"
  on moderation_logs for insert
  with check (exists(select 1 from admin_users where id = auth.uid()));

-- Create index for faster queries
create index idx_moderation_logs_admin_id on moderation_logs(admin_id);
create index idx_moderation_logs_created_at on moderation_logs(created_at);
