-- Products table
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price decimal(10, 2) not null check (price > 0),
  stock integer not null default 0 check (stock >= 0),
  image_url text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Customers table
create table customers (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text not null,
  phone text,
  address text,
  city text,
  country text,
  postal_code text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Orders table
create table orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references customers(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
  total_price decimal(10, 2) not null check (total_price >= 0),
  shipping_address text,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Order items table
create table order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references orders(id) on delete cascade,
  product_id uuid not null references products(id) on delete restrict,
  quantity integer not null check (quantity > 0),
  price_at_purchase decimal(10, 2) not null check (price_at_purchase > 0),
  created_at timestamp with time zone default now()
);

-- Indexes for performance
create index idx_orders_customer_id on orders(customer_id);
create index idx_orders_created_at on orders(created_at desc);
create index idx_order_items_order_id on order_items(order_id);
create index idx_order_items_product_id on order_items(product_id);
create index idx_products_created_at on products(created_at desc);

-- Enable RLS
alter table products enable row level security;
alter table customers enable row level security;
alter table orders enable row level security;
alter table order_items enable row level security;

-- RLS Policies for Products (public read access)
create policy "Anyone can view products"
  on products for select
  using (true);

create policy "Only admins can insert products"
  on products for insert
  with check (false);

create policy "Only admins can update products"
  on products for update
  using (false);

create policy "Only admins can delete products"
  on products for delete
  using (false);

-- RLS Policies for Customers (users can only see their own data)
create policy "Users can view their own customer profile"
  on customers for select
  using (auth.uid() = id);

create policy "Users can insert their own customer profile"
  on customers for insert
  with check (auth.uid() = id);

create policy "Users can update their own customer profile"
  on customers for update
  using (auth.uid() = id);

-- RLS Policies for Orders
create policy "Users can view their own orders"
  on orders for select
  using (auth.uid() = customer_id);

create policy "Users can insert orders for themselves"
  on orders for insert
  with check (auth.uid() = customer_id);

create policy "Users can update their own orders"
  on orders for update
  using (auth.uid() = customer_id);

-- RLS Policies for Order Items
create policy "Users can view items in their own orders"
  on order_items for select
  using (
    exists (
      select 1 from orders
      where orders.id = order_items.order_id
      and orders.customer_id = auth.uid()
    )
  );

create policy "Users can insert items in their own orders"
  on order_items for insert
  with check (
    exists (
      select 1 from orders
      where orders.id = order_id
      and orders.customer_id = auth.uid()
    )
  );
