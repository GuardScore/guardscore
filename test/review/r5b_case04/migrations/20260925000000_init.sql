-- Create products table
create table products (
  id bigserial primary key,
  name text not null,
  description text,
  price numeric(10, 2) not null check (price > 0),
  stock_quantity integer not null default 0 check (stock_quantity >= 0),
  image_url text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create orders table
create table orders (
  id bigserial primary key,
  user_id uuid not null references auth.users on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
  total_amount numeric(10, 2) not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create order_items table (join table between orders and products)
create table order_items (
  id bigserial primary key,
  order_id bigint not null references orders on delete cascade,
  product_id bigint not null references products on delete restrict,
  quantity integer not null check (quantity > 0),
  unit_price numeric(10, 2) not null check (unit_price > 0),
  created_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index idx_orders_user_id on orders(user_id);
create index idx_order_items_order_id on order_items(order_id);
create index idx_order_items_product_id on order_items(product_id);

-- Enable RLS
alter table products enable row level security;
alter table orders enable row level security;
alter table order_items enable row level security;

-- RLS Policy: Products are public readable
create policy "Products are publicly readable"
  on products for select
  using (true);

-- RLS Policy: Orders - users can only see their own orders
create policy "Users can view their own orders"
  on orders for select
  using (auth.uid() = user_id);

create policy "Users can insert their own orders"
  on orders for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own orders"
  on orders for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- RLS Policy: Order items - users can see items in their orders
create policy "Users can view order items from their orders"
  on order_items for select
  using (
    exists (
      select 1 from orders o
      where o.id = order_items.order_id
      and o.user_id = auth.uid()
    )
  );

create policy "Users can insert order items for their orders"
  on order_items for insert
  with check (
    exists (
      select 1 from orders o
      where o.id = order_items.order_id
      and o.user_id = auth.uid()
    )
  );
