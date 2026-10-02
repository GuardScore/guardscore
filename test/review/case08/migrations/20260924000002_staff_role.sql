-- Create staff table
create table if not exists staff (
  id bigserial primary key,
  user_id uuid references auth.users(id) on delete cascade not null unique,
  email text not null,
  first_name text not null,
  last_name text not null,
  role text not null default 'staff' check (role in ('staff', 'manager', 'admin')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS on staff table
alter table staff enable row level security;

-- Staff can view their own profile
create policy "Staff can view their own profile"
  on staff for select
  using (auth.uid() = user_id);

-- Create index on staff user_id for performance
create index if not exists idx_staff_user_id on staff(user_id);

-- Create a security-definer function to check if user is staff
-- This bypasses RLS to safely check staff status
create or replace function is_staff(user_id uuid) returns boolean as $$
begin
  return exists (select 1 from staff where staff.user_id = user_id);
end;
$$ language plpgsql security definer set search_path = public;

-- Fix orders RLS
alter table orders enable row level security;
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'orders' loop
    execute format('drop policy %I on %I.%I', p.policyname, 'public', 'orders');
  end loop;
end $$;

-- Customers access their own orders, staff access all orders
create policy "orders_access" on orders for all to authenticated
  using (
    (customer_id = (select id from customers where user_id = auth.uid()))
    or
    is_staff(auth.uid())
  )
  with check (
    (customer_id = (select id from customers where user_id = auth.uid()))
    or
    is_staff(auth.uid())
  );

-- Fix order_items RLS
alter table order_items enable row level security;
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'order_items' loop
    execute format('drop policy %I on %I.%I', p.policyname, 'public', 'order_items');
  end loop;
end $$;

-- Access order items if can access the order
create policy "order_items_access" on order_items for all to authenticated
  using (
    order_id in (
      select id from orders where
        (customer_id = (select id from customers where user_id = auth.uid()))
        or
        is_staff(auth.uid())
    )
  )
  with check (
    order_id in (
      select id from orders where
        (customer_id = (select id from customers where user_id = auth.uid()))
        or
        is_staff(auth.uid())
    )
  );
