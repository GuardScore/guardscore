-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Products table (public catalog)
create table public.products (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  description text,
  price decimal(10, 2) not null check (price >= 0),
  stock integer not null default 0 check (stock >= 0),
  image_url text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Customers table (linked to auth.users)
create table public.customers (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  first_name text not null,
  last_name text not null,
  email text not null,
  phone text,
  address text,
  city text,
  state text,
  postal_code text,
  country text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Orders table (customer orders)
create table public.orders (
  id uuid primary key default uuid_generate_v4(),
  customer_id uuid not null references public.customers(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  total_amount decimal(10, 2) not null check (total_amount >= 0),
  shipping_address text not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Order items table (products in each order)
create table public.order_items (
  id uuid primary key default uuid_generate_v4(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid not null references public.products(id),
  quantity integer not null check (quantity > 0),
  unit_price decimal(10, 2) not null check (unit_price >= 0),
  created_at timestamp with time zone default now()
);

-- Enable RLS
alter table public.products enable row level security;
alter table public.customers enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

-- Products: everyone can read, only admins can create/update/delete
create policy "anyone_can_read_products" on public.products
  for select using (true);

create policy "admins_can_modify_products" on public.products
  for insert with check (auth.jwt() ->> 'role' = 'admin');

create policy "admins_can_update_products" on public.products
  for update using (auth.jwt() ->> 'role' = 'admin');

create policy "admins_can_delete_products" on public.products
  for delete using (auth.jwt() ->> 'role' = 'admin');

-- Customers: users can read only their own, admins can read all
create policy "users_can_read_own_customer" on public.customers
  for select using (auth.uid() = user_id or auth.jwt() ->> 'role' = 'admin');

create policy "users_can_insert_customer" on public.customers
  for insert with check (auth.uid() = user_id);

create policy "users_can_update_own_customer" on public.customers
  for update using (auth.uid() = user_id or auth.jwt() ->> 'role' = 'admin');

-- Orders: users can read only their own orders
create policy "users_can_read_own_orders" on public.orders
  for select using (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

create policy "users_can_insert_orders" on public.orders
  for insert with check (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

create policy "users_can_update_own_orders" on public.orders
  for update using (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  ) with check (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

-- Order items: users can read items only from their orders
create policy "users_can_read_own_order_items" on public.order_items
  for select using (
    order_id in (
      select id from public.orders
      where customer_id in (
        select id from public.customers where user_id = auth.uid()
      )
    )
  );

create policy "users_can_insert_order_items" on public.order_items
  for insert with check (
    order_id in (
      select id from public.orders
      where customer_id in (
        select id from public.customers where user_id = auth.uid()
      )
    )
  );

-- Indexes for common queries
create index idx_products_created_at on public.products(created_at);
create index idx_customers_user_id on public.customers(user_id);
create index idx_orders_customer_id on public.orders(customer_id);
create index idx_orders_created_at on public.orders(created_at);
create index idx_order_items_order_id on public.order_items(order_id);
create index idx_order_items_product_id on public.order_items(product_id);
