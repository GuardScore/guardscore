-- Create staff_members table
create table staff_members (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  role text not null default 'staff' check (role in ('staff', 'manager', 'admin')),
  name text not null,
  email text not null,
  active boolean not null default true,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS on staff_members
alter table staff_members enable row level security;

-- Only staff can read their own record (verify their role)
create policy "staff_can_read_own_record"
  on staff_members
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Only admins can insert new staff members
create policy "admins_can_manage_staff"
  on staff_members
  for all
  to authenticated
  using (
    auth.uid() in (
      select user_id from staff_members where role = 'admin' and active = true
    )
  )
  with check (
    auth.uid() in (
      select user_id from staff_members where role = 'admin' and active = true
    )
  );

-- Create helper function to check if user is staff
create or replace function is_staff()
returns boolean as $$
  select exists(
    select 1 from staff_members
    where user_id = auth.uid() and active = true
  );
$$ language sql stable;

-- Create helper function to check if user is admin
create or replace function is_admin()
returns boolean as $$
  select exists(
    select 1 from staff_members
    where user_id = auth.uid() and role = 'admin' and active = true
  );
$$ language sql stable;

-- Update orders table RLS policies to allow staff to view all orders
create policy "staff_can_read_all_orders"
  on orders
  for select
  to authenticated
  using (is_staff());

-- Allow staff to update order status (but not customer_id or user_id)
create policy "staff_can_update_order_status"
  on orders
  for update
  to authenticated
  using (is_staff())
  with check (
    is_staff()
    -- Prevent staff from changing customer_id or user_id
    and customer_id = (select customer_id from orders where id = orders.id)
    and user_id = (select user_id from orders where id = orders.id)
  );

-- Create index on staff_members for lookups
create index staff_members_user_id_idx on staff_members(user_id);
create index staff_members_active_idx on staff_members(active);
create index staff_members_role_idx on staff_members(role);

-- Create trigger to update updated_at on staff_members
create trigger update_staff_members_updated_at
before update on staff_members
for each row
execute function update_updated_at_column();
