-- Create products table (public catalog)
create table if not exists products (
  id bigserial primary key,
  name text not null,
  description text,
  price decimal(10, 2) not null,
  stock_quantity integer not null default 0,
  sku text unique not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create customers table (authenticated users)
create table if not exists customers (
  id bigserial primary key,
  user_id uuid references auth.users(id) on delete cascade not null unique,
  email text not null,
  first_name text not null,
  last_name text not null,
  phone text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create orders table
create table if not exists orders (
  id bigserial primary key,
  customer_id bigint references customers(id) on delete restrict not null,
  status text not null default 'pending' check (status in ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
  total_amount decimal(10, 2) not null,
  shipping_address text,
  billing_address text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create order items table
create table if not exists order_items (
  id bigserial primary key,
  order_id bigint references orders(id) on delete cascade not null,
  product_id bigint references products(id) on delete restrict not null,
  quantity integer not null check (quantity > 0),
  unit_price decimal(10, 2) not null,
  created_at timestamp with time zone default now()
);

-- Create indexes for performance
create index if not exists idx_customers_user_id on customers(user_id);
create index if not exists idx_orders_customer_id on orders(customer_id);
create index if not exists idx_orders_status on orders(status);
create index if not exists idx_order_items_order_id on order_items(order_id);
create index if not exists idx_order_items_product_id on order_items(product_id);

-- Enable Row Level Security
alter table products enable row level security;
alter table customers enable row level security;
alter table orders enable row level security;
alter table order_items enable row level security;

-- RLS Policies for products (public read)
create policy "Products are viewable by everyone"
  on products for select using (true);

-- RLS Policies for customers (users can only view/edit their own)
create policy "Customers can view their own profile"
  on customers for select
  using (auth.uid() = user_id);

create policy "Customers can update their own profile"
  on customers for update
  using (auth.uid() = user_id);

create policy "Customers can insert their own profile"
  on customers for insert
  with check (auth.uid() = user_id);

-- RLS Policies for orders (users can only see their own orders)
create policy "Customers can view their own orders"
  on orders for select
  using (
    customer_id = (
      select id from customers where user_id = auth.uid()
    )
  );

create policy "Customers can insert their own orders"
  on orders for insert
  with check (
    customer_id = (
      select id from customers where user_id = auth.uid()
    )
  );

create policy "Customers can update their own orders"
  on orders for update
  using (
    customer_id = (
      select id from customers where user_id = auth.uid()
    )
  );

-- RLS Policies for order_items (users can view items in their own orders)
create policy "Customers can view order items in their orders"
  on order_items for select
  using (
    order_id in (
      select o.id from orders o
      join customers c on o.customer_id = c.id
      where c.user_id = auth.uid()
    )
  );

create policy "Customers can insert order items in their orders"
  on order_items for insert
  with check (
    order_id in (
      select o.id from orders o
      join customers c on o.customer_id = c.id
      where c.user_id = auth.uid()
    )
  );
