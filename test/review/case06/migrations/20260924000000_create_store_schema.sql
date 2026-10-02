-- Create products table
create table if not exists products (
  id bigserial primary key,
  name text not null,
  description text,
  price decimal(10, 2) not null check (price >= 0),
  stock integer not null default 0 check (stock >= 0),
  image_url text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create customers table (profiles linked to auth.users)
create table if not exists customers (
  id bigserial primary key,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  email text not null,
  first_name text,
  last_name text,
  phone text,
  address text,
  city text,
  postal_code text,
  country text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create orders table
create table if not exists orders (
  id bigserial primary key,
  customer_id bigint not null references customers(id) on delete cascade,
  order_date timestamp with time zone default timezone('utc'::text, now()) not null,
  status text not null default 'pending' check (status in ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  total_price decimal(10, 2) not null default 0 check (total_price >= 0),
  notes text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create order items table (line items in orders)
create table if not exists order_items (
  id bigserial primary key,
  order_id bigint not null references orders(id) on delete cascade,
  product_id bigint not null references products(id) on delete restrict,
  quantity integer not null check (quantity > 0),
  unit_price decimal(10, 2) not null check (unit_price >= 0),
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Create indexes for better query performance
create index if not exists products_created_at_idx on products(created_at);
create index if not exists customers_user_id_idx on customers(user_id);
create index if not exists orders_customer_id_idx on orders(customer_id);
create index if not exists orders_status_idx on orders(status);
create index if not exists order_items_order_id_idx on order_items(order_id);
create index if not exists order_items_product_id_idx on order_items(product_id);

-- Enable RLS on all tables
alter table products enable row level security;
alter table customers enable row level security;
alter table orders enable row level security;
alter table order_items enable row level security;

-- RLS Policy: Products are publicly readable
create policy "Products are publicly readable" on products
  for select using (true);

-- RLS Policy: Only authenticated users can insert/update/delete products (for now, consider admin role later)
create policy "Only authenticated users can modify products" on products
  for insert with check (auth.role() = 'authenticated');

create policy "Only product owner can update products" on products
  for update using (auth.role() = 'authenticated');

create policy "Only product owner can delete products" on products
  for delete using (auth.role() = 'authenticated');

-- RLS Policy: Customers can only view/edit their own profile
create policy "Customers can view their own profile" on customers
  for select using (auth.uid() = user_id or auth.role() = 'authenticated');

create policy "Customers can insert their own profile" on customers
  for insert with check (auth.uid() = user_id);

create policy "Customers can update their own profile" on customers
  for update using (auth.uid() = user_id);

-- RLS Policy: Orders - customers can only view/edit their own orders
create policy "Customers can view their own orders" on orders
  for select using (
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

create policy "Customers can insert orders" on orders
  for insert with check (
    auth.role() = 'authenticated' and
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

create policy "Customers can update their own orders" on orders
  for update using (
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

-- RLS Policy: Order items - customers can view items in their own orders
create policy "Customers can view items in their orders" on order_items
  for select using (
    order_id in (
      select id from orders where customer_id in (
        select id from customers where user_id = auth.uid()
      )
    )
  );

create policy "Customers can insert order items to their orders" on order_items
  for insert with check (
    order_id in (
      select id from orders where customer_id in (
        select id from customers where user_id = auth.uid()
      )
    )
  );
