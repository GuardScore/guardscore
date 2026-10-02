-- Create staff_members table to track staff users
create table if not exists staff_members (
  id bigserial primary key,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  role text not null default 'staff' check (role in ('staff', 'manager', 'admin')),
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create index on user_id for faster lookups
create index if not exists staff_members_user_id_idx on staff_members(user_id);

-- Enable RLS on staff_members
alter table staff_members enable row level security;

-- RLS Policy: Only admins can view/manage staff members (for now, allow all authenticated users to see public info)
create policy "Only authenticated users can view staff members" on staff_members
  for select using (true);

create policy "Only admins can manage staff members" on staff_members
  for insert with check (false);

create policy "Only admins can update staff members" on staff_members
  for update using (false);

create policy "Only admins can delete staff members" on staff_members
  for delete using (false);

-- Update RLS policies for orders to allow staff to view all orders
create policy "Staff can view all orders" on orders
  for select using (
    exists (select 1 from staff_members where user_id = auth.uid())
  );

-- Allow staff to update order status and notes
create policy "Staff can update orders" on orders
  for update using (
    exists (select 1 from staff_members where user_id = auth.uid())
  ) with check (
    exists (select 1 from staff_members where user_id = auth.uid())
  );

-- Allow staff to view order items for all orders
create policy "Staff can view all order items" on order_items
  for select using (
    exists (select 1 from staff_members where user_id = auth.uid())
  );

-- Create a helper function to check if a user is staff
create or replace function is_staff(user_id uuid)
returns boolean as $$
  select exists (select 1 from staff_members where staff_members.user_id = user_id);
$$ language sql security definer;
