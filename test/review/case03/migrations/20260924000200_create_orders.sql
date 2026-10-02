-- Create orders table
create table orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references customers(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
  total_amount numeric(10, 2) not null check (total_amount >= 0),
  shipping_address text,
  notes text,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table orders enable row level security;

-- Users can read their own orders
create policy "orders_are_readable_by_owner"
  on orders
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Users can create orders
create policy "orders_are_insertable_by_owner"
  on orders
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Users can update their own orders (for things like cancellation)
create policy "orders_are_updatable_by_owner"
  on orders
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Create indexes for common queries
create index orders_user_id_idx on orders(user_id);
create index orders_customer_id_idx on orders(customer_id);
create index orders_created_at_idx on orders(created_at desc);
create index orders_status_idx on orders(status);
