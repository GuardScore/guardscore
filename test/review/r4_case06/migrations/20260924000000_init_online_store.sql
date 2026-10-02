-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Create profiles table (extends auth.users)
create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text unique not null,
  full_name text,
  phone text,
  address text,
  city text,
  state text,
  postal_code text,
  country text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create products table
create table if not exists public.products (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  description text,
  price numeric(10, 2) not null check (price > 0),
  stock_quantity integer not null default 0 check (stock_quantity >= 0),
  category text,
  image_url text,
  is_active boolean default true,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create orders table
create table if not exists public.orders (
  id uuid primary key default uuid_generate_v4(),
  customer_id uuid not null references public.profiles on delete cascade,
  total_amount numeric(10, 2) not null check (total_amount >= 0),
  status text not null default 'pending' check (status in ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  shipping_address text not null,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create order_items table
create table if not exists public.order_items (
  id uuid primary key default uuid_generate_v4(),
  order_id uuid not null references public.orders on delete cascade,
  product_id uuid not null references public.products on delete restrict,
  quantity integer not null check (quantity > 0),
  unit_price numeric(10, 2) not null check (unit_price > 0),
  subtotal numeric(10, 2) not null check (subtotal >= 0),
  created_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index if not exists idx_profiles_email on public.profiles(email);
create index if not exists idx_products_category on public.products(category);
create index if not exists idx_products_is_active on public.products(is_active);
create index if not exists idx_orders_customer_id on public.orders(customer_id);
create index if not exists idx_orders_status on public.orders(status);
create index if not exists idx_orders_created_at on public.orders(created_at);
create index if not exists idx_order_items_order_id on public.order_items(order_id);
create index if not exists idx_order_items_product_id on public.order_items(product_id);

-- Enable RLS
alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

-- Profiles policies
create policy "Users can view their own profile" on public.profiles
  for select using (auth.uid() = id);

create policy "Users can update their own profile" on public.profiles
  for update using (auth.uid() = id);

create policy "Users can insert their own profile" on public.profiles
  for insert with check (auth.uid() = id);

-- Products policies (public read)
create policy "Anyone can view active products" on public.products
  for select using (is_active = true);

create policy "Only authenticated users can view all products" on public.products
  for select using (auth.role() = 'authenticated');

-- Orders policies
create policy "Users can view their own orders" on public.orders
  for select using (auth.uid() = customer_id);

create policy "Users can create their own orders" on public.orders
  for insert with check (auth.uid() = customer_id);

create policy "Users can update their own orders" on public.orders
  for update using (auth.uid() = customer_id);

-- Order items policies
create policy "Users can view items in their own orders" on public.order_items
  for select using (
    exists (
      select 1 from public.orders
      where orders.id = order_items.order_id
      and orders.customer_id = auth.uid()
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

-- Trigger to auto-create profile on user signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$ language plpgsql security definer set search_path = public;

create or replace trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Function to update profile updated_at timestamp
create or replace function public.update_profile_timestamp()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger update_profiles_timestamp before update on public.profiles
  for each row execute procedure update_profile_timestamp();

-- Function to calculate order total from items
create or replace function public.calculate_order_total()
returns trigger as $$
declare
  v_total numeric;
begin
  select coalesce(sum(subtotal), 0) into v_total
  from public.order_items
  where order_id = new.order_id;

  update public.orders
  set total_amount = v_total
  where id = new.order_id;

  return new;
end;
$$ language plpgsql;

create trigger calculate_order_total_on_item_insert after insert on public.order_items
  for each row execute procedure calculate_order_total();

create trigger calculate_order_total_on_item_update after update on public.order_items
  for each row execute procedure calculate_order_total();

create trigger calculate_order_total_on_item_delete after delete on public.order_items
  for each row execute procedure calculate_order_total();

-- Function to reduce product stock when order item is created
create or replace function public.reduce_product_stock()
returns trigger as $$
begin
  update public.products
  set stock_quantity = stock_quantity - new.quantity
  where id = new.product_id
  and stock_quantity >= new.quantity;

  if not found then
    raise exception 'Insufficient stock for product %', new.product_id;
  end if;

  return new;
end;
$$ language plpgsql;

create trigger reduce_stock_on_order_item after insert on public.order_items
  for each row execute procedure reduce_product_stock();

-- Sample data for testing
insert into public.products (name, description, price, stock_quantity, category, is_active) values
  ('Wireless Headphones', 'High-quality Bluetooth headphones with noise cancellation', 79.99, 50, 'Electronics', true),
  ('Coffee Maker', 'Programmable drip coffee maker with thermal carafe', 49.99, 30, 'Appliances', true),
  ('Running Shoes', 'Professional grade running shoes with arch support', 119.99, 40, 'Footwear', true),
  ('Desk Lamp', 'LED desk lamp with adjustable brightness', 39.99, 25, 'Office', true),
  ('Water Bottle', 'Insulated stainless steel water bottle, 32oz', 24.99, 100, 'Sports', true);
