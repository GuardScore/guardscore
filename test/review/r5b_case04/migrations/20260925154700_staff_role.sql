-- Create profiles table to track user roles
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  role text not null default 'customer' check (role in ('customer', 'staff', 'admin')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS on profiles
alter table profiles enable row level security;

-- RLS: Users can view their own profile, staff can view all
create policy "Users can view their own profile"
  on profiles for select
  using (auth.uid() = id or (select role from profiles where id = auth.uid()) = 'staff');

-- RLS: Only admins can update roles
create policy "Only admins can update roles"
  on profiles for update
  using ((select role from profiles where id = auth.uid()) = 'admin')
  with check ((select role from profiles where id = auth.uid()) = 'admin');

-- Helper function to check if user is staff
create or replace function is_staff(user_id uuid)
returns boolean as $$
  select coalesce((select role from profiles where id = user_id) = 'staff', false);
$$ language sql stable;

-- Helper function to check if user is admin
create or replace function is_admin(user_id uuid)
returns boolean as $$
  select coalesce((select role from profiles where id = user_id) = 'admin', false);
$$ language sql stable;

-- Update orders RLS: staff can see all orders and update status
drop policy "Users can view their own orders" on orders;
create policy "Users can view their own orders, staff can view all"
  on orders for select
  using (auth.uid() = user_id or is_staff(auth.uid()));

-- Allow staff to update order status
drop trigger if exists "lock_orders_money_status" on orders;
drop function if exists public."lock_orders_money_status"();

create or replace function lock_orders_money_status()
returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."status" := 'pending'::text;
    else
      -- Allow staff to change status, but regular users cannot
      if new."status" is distinct from old."status" and not is_staff(auth.uid()) then
        raise exception 'permission denied: only staff can change status';
      end if;
    end if;
  end if;
  return new;
end $lock$;

create trigger "lock_orders_money_status" before insert or update on orders for each row execute function lock_orders_money_status();

-- Update order_items RLS: staff can see all items
drop policy "Users can view order items from their orders" on order_items;
create policy "Users can view order items from their orders, staff can view all"
  on order_items for select
  using (
    auth.uid() = (select user_id from orders o where o.id = order_items.order_id)
    or is_staff(auth.uid())
  );

-- Update order_history view to include staff access
drop view if exists order_history;
create view order_history as
select
  o.id as order_id,
  o.user_id,
  o.status,
  o.total_amount,
  o.created_at as order_date,
  o.updated_at as order_updated_at,
  oi.id as item_id,
  oi.product_id,
  p.name as product_name,
  p.image_url,
  oi.quantity,
  oi.unit_price,
  (oi.quantity * oi.unit_price) as item_total
from orders o
left join order_items oi on o.id = oi.order_id
left join products p on oi.product_id = p.id
where auth.uid() = o.user_id or is_staff(auth.uid())
order by o.created_at desc, oi.id;

alter view order_history set (security_invoker = true);
