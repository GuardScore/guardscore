-- Create admins table to track admin users
create table admins (
  id bigint primary key generated always as identity,
  user_id uuid not null unique references auth.users on delete cascade,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on admins table
alter table admins enable row level security;

-- Only admins can view the admins table (for the admin page)
create policy "Only admins can view admins"
  on admins
  for select
  using (exists (select 1 from admins where admins.user_id = auth.uid()));

-- Update notes RLS policy to allow admins to see all notes
create policy "Admins can view all notes"
  on notes
  for select
  using (exists (select 1 from admins where admins.user_id = auth.uid()));

-- Create an index on user_id for faster admin checks
create index admins_user_id_idx on admins (user_id);
