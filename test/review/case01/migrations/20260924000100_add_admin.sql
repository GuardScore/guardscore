-- Create profiles table to track user roles
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  is_admin boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS on profiles
alter table profiles enable row level security;

-- Allow users to read their own profile
create policy "Users can read their own profile"
  on profiles for select
  using (auth.uid() = id);

-- Allow admins to read all profiles
create policy "Admins can read all profiles"
  on profiles for select
  using (
    exists (
      select 1 from profiles where id = auth.uid() and is_admin = true
    )
  );

-- Create a function to check if user is admin
create or replace function is_admin(user_id uuid)
returns boolean as $$
  select is_admin from profiles where id = user_id;
$$ language sql security definer;

-- Modify notes table to allow admins to see all notes
create policy "Admins can read all notes"
  on notes for select
  using (
    exists (
      select 1 from profiles where id = auth.uid() and is_admin = true
    )
  );

-- Admins can delete any note
create policy "Admins can delete any note"
  on notes for delete
  using (
    exists (
      select 1 from profiles where id = auth.uid() and is_admin = true
    )
  );

-- Create audit log for moderation
create table moderation_log (
  id uuid default gen_random_uuid() primary key,
  admin_id uuid not null references auth.users on delete cascade,
  note_id uuid references notes on delete set null,
  action text not null,
  reason text,
  created_at timestamp with time zone default now()
);

-- Create index on moderation log
create index moderation_log_admin_id_idx on moderation_log(admin_id);
create index moderation_log_created_at_idx on moderation_log(created_at);

-- Enable RLS on moderation log
alter table moderation_log enable row level security;

-- Only admins can read moderation log
create policy "Admins can read moderation log"
  on moderation_log for select
  using (
    exists (
      select 1 from profiles where id = auth.uid() and is_admin = true
    )
  );

-- Admins can insert moderation log
create policy "Admins can insert moderation log"
  on moderation_log for insert
  with check (
    exists (
      select 1 from profiles where id = auth.uid() and is_admin = true
    )
  );
