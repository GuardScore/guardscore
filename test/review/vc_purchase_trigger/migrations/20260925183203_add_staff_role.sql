-- Create staff_members table to designate staff users
create table staff_members (
  id uuid primary key references auth.users on delete cascade,
  role text not null default 'staff' check (role in ('staff', 'manager', 'admin')),
  created_at timestamp with time zone default now()
);

-- Create index for staff role lookups
create index idx_staff_members_id on staff_members(id);

-- Enable RLS on staff_members
alter table staff_members enable row level security;

-- Only staff can see the staff table (security: don't leak who is staff to non-staff)
create policy "only staff can view staff members" on staff_members
  for select using (exists (select 1 from staff_members where id = auth.uid()));

-- Create a helper function to check if current user is staff
create or replace function is_staff()
returns boolean as $$
  select exists (select 1 from staff_members where id = auth.uid());
$$ language sql security definer;

-- Drop and recreate order RLS policies to allow staff access
drop policy if exists "users can view their own orders" on orders;
drop policy if exists "users can create orders" on orders;
drop policy if exists "users can update their own orders" on orders;

-- New order policies: customers see their own, staff sees all
create policy "view own or staff view all orders" on orders
  for select using (
    auth.uid() = customer_id or is_staff()
  );

create policy "customers create orders, staff can insert" on orders
  for insert with check (
    auth.uid() = customer_id or is_staff()
  );

create policy "customers update own, staff update any" on orders
  for update using (
    auth.uid() = customer_id or is_staff()
  );

create policy "staff can delete orders" on orders
  for delete using (is_staff());

-- Drop and recreate order_items RLS policies to allow staff access
drop policy if exists "users can view order items for their own orders" on order_items;
drop policy if exists "users can add items to their own orders" on order_items;

create policy "view items in own orders or staff view all" on order_items
  for select using (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and (orders.customer_id = auth.uid() or is_staff())
    )
  );

create policy "add items to own orders or staff can add" on order_items
  for insert with check (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and (orders.customer_id = auth.uid() or is_staff())
    )
  );

create policy "staff can delete order items" on order_items
  for delete using (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and is_staff()
    )
  );

-- Update trigger to allow staff to change status
create or replace function vc_lock_orders_status() returns trigger language plpgsql as $lock$
begin
  if not is_staff() and current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."status" := 'pending'::text;
    else
      if new."status" is distinct from old."status" then
        raise exception 'permission denied: only staff can change status';
      end if;
    end if;
  end if;
  return new;
end $lock$;

-- Update trigger to allow staff to change total_amount
create or replace function vc_lock_orders_total_amount() returns trigger language plpgsql as $lock$
begin
  if not is_staff() and current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'UPDATE' then
      if new."total_amount" is distinct from old."total_amount" then
        raise exception 'permission denied: only staff can change total_amount';
      end if;
    end if;
  end if;
  return new;
end $lock$;

-- Create a function for staff to update order status
create or replace function update_order_status(
  order_id_param uuid,
  new_status text
)
returns orders as $$
declare
  updated_order orders;
begin
  if not is_staff() then
    raise exception 'permission denied: only staff can update order status';
  end if;

  if new_status not in ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled') then
    raise exception 'invalid status: must be one of pending, confirmed, shipped, delivered, cancelled';
  end if;

  update orders
  set status = new_status, updated_at = now()
  where id = order_id_param
  returning * into updated_order;

  return updated_order;
end;
$$ language plpgsql security definer;

-- Create a function for staff to view all orders with customer info
create or replace function get_all_orders()
returns table (
  order_id uuid,
  customer_id uuid,
  customer_name text,
  customer_email text,
  status text,
  total_amount decimal,
  item_count bigint,
  order_date timestamp with time zone
) as $$
begin
  if not is_staff() then
    raise exception 'permission denied: only staff can view all orders';
  end if;

  return query
  select
    o.id,
    o.customer_id,
    cp.full_name,
    u.email,
    o.status,
    o.total_amount,
    count(oi.id),
    o.created_at
  from orders o
  join customer_profiles cp on o.customer_id = cp.id
  join auth.users u on o.customer_id = u.id
  left join order_items oi on o.id = oi.order_id
  group by o.id, o.customer_id, cp.full_name, u.email, o.status, o.total_amount, o.created_at
  order by o.created_at desc;
end;
$$ language plpgsql security definer;
