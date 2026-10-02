-- Create products table
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price decimal(10, 2) not null,
  stock_quantity integer not null default 0,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create customer profiles table (extends auth.users)
create table customer_profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  phone text,
  address text,
  city text,
  postal_code text,
  country text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create orders table
create table orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references customer_profiles on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  total_amount decimal(10, 2) not null default 0,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create order items table (junction table)
create table order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references orders on delete cascade,
  product_id uuid not null references products on delete restrict,
  quantity integer not null check (quantity > 0),
  price_at_purchase decimal(10, 2) not null,
  created_at timestamp with time zone default now()
);

-- Create indexes for performance
create index idx_orders_customer_id on orders(customer_id);
create index idx_orders_status on orders(status);
create index idx_orders_created_at on orders(created_at);
create index idx_order_items_order_id on order_items(order_id);
create index idx_order_items_product_id on order_items(product_id);
create index idx_products_name on products(name);

-- Enable RLS (Row Level Security)
alter table products enable row level security;
alter table customer_profiles enable row level security;
alter table orders enable row level security;
alter table order_items enable row level security;

-- Public access to products (anyone can read)
create policy "products are public" on products
  for select using (true);

-- Customer profile policies
create policy "users can view their own profile" on customer_profiles
  for select using (auth.uid() = id);

create policy "users can update their own profile" on customer_profiles
  for update using (auth.uid() = id);

create policy "users can insert their own profile" on customer_profiles
  for insert with check (auth.uid() = id);

-- Order policies (users can only see their own orders)
create policy "users can view their own orders" on orders
  for select using (auth.uid() = customer_id);

create policy "users can create orders" on orders
  for insert with check (auth.uid() = customer_id);

create policy "users can update their own orders" on orders
  for update using (auth.uid() = customer_id);

-- Order items policies (users can see items in their own orders)
create policy "users can view order items for their own orders" on order_items
  for select using (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and orders.customer_id = auth.uid()
    )
  );

create policy "users can add items to their own orders" on order_items
  for insert with check (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and orders.customer_id = auth.uid()
    )
  );
