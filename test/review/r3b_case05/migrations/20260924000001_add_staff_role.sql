-- Add role column to customers table
alter table customers add column role text not null default 'customer' check (role in ('customer', 'staff', 'admin'));

-- Create index for role lookup
create index idx_customers_role on customers(role);

-- Helper function to check if user is staff or admin
create or replace function is_staff_or_admin()
returns boolean as $$
begin
  return exists (
    select 1 from customers
    where id = auth.uid()
    and role in ('staff', 'admin')
  );
end;
$$ language plpgsql security definer;

-- Update RLS policies for Orders to allow staff to see all orders
drop policy "Users can view their own orders" on orders;

create policy "Users can view their own orders or staff can view all"
  on orders for select
  using (
    auth.uid() = customer_id
    or is_staff_or_admin()
  );

-- Update RLS policies for Orders to allow staff to update order status
drop policy "Users can update their own orders" on orders;

create policy "Users can update their own orders or staff can update any"
  on orders for update
  using (
    auth.uid() = customer_id
    or is_staff_or_admin()
  )
  with check (
    auth.uid() = customer_id
    or is_staff_or_admin()
  );

-- Update RLS policies for Order Items to allow staff to view all
drop policy "Users can view items in their own orders" on order_items;

create policy "Users can view items in their own orders or staff can view all"
  on order_items for select
  using (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and (orders.customer_id = auth.uid() or is_staff_or_admin())
    )
  );
