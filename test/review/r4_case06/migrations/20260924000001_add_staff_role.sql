-- Add role column to profiles table
alter table public.profiles add column if not exists role text default 'customer' check (role in ('customer', 'staff', 'admin'));

-- Create index on role for faster staff queries
create index if not exists idx_profiles_role on public.profiles(role);

-- Drop existing orders policies to replace them with role-aware versions
drop policy if exists "Users can view their own orders" on public.orders;
drop policy if exists "Users can create their own orders" on public.orders;
drop policy if exists "Users can update their own orders" on public.orders;

-- New orders policies with role support
create policy "Users can view their own orders or staff can view all" on public.orders
  for select using (
    auth.uid() = customer_id
    or exists (
      select 1 from public.profiles
      where id = auth.uid()
      and role in ('staff', 'admin')
    )
  );

create policy "Users can create their own orders" on public.orders
  for insert with check (auth.uid() = customer_id);

create policy "Users can update their own orders or staff can update any" on public.orders
  for update using (
    auth.uid() = customer_id
    or exists (
      select 1 from public.profiles
      where id = auth.uid()
      and role in ('staff', 'admin')
    )
  );

-- Drop existing order_items policies to ensure consistency
drop policy if exists "Users can view items in their own orders" on public.order_items;
drop policy if exists "Users can insert items to their own orders" on public.order_items;

-- New order_items policies with role support
create policy "Users can view items in their own orders or staff can view all" on public.order_items
  for select using (
    exists (
      select 1 from public.orders
      where orders.id = order_items.order_id
      and (
        orders.customer_id = auth.uid()
        or exists (
          select 1 from public.profiles
          where id = auth.uid()
          and role in ('staff', 'admin')
        )
      )
    )
  );

create policy "Users can insert items to their own orders" on public.order_items
  for insert with check (
    exists (
      select 1 from public.orders
      where orders.id = order_items.order_id
      and orders.customer_id = auth.uid()
    )
  );

-- Create a helper function to promote a user to staff (useful for admin tasks)
create or replace function public.set_user_role(user_id uuid, new_role text)
returns void as $$
declare
  v_is_admin boolean;
begin
  -- Check if current user is admin (only admins can change roles)
  select exists(
    select 1 from public.profiles
    where id = auth.uid()
    and role = 'admin'
  ) into v_is_admin;

  if not v_is_admin then
    raise exception 'Only admins can change user roles';
  end if;

  update public.profiles
  set role = new_role
  where id = user_id;
end;
$$ language plpgsql security definer set search_path = public;
