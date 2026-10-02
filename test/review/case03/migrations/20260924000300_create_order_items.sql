-- Create order_items table
create table order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references orders(id) on delete cascade,
  product_id uuid not null references products(id) on delete restrict,
  quantity integer not null check (quantity > 0),
  price_at_purchase numeric(10, 2) not null check (price_at_purchase > 0),
  created_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table order_items enable row level security;

-- Users can read items in their own orders
create policy "order_items_are_readable_by_order_owner"
  on order_items
  for select
  to authenticated
  using (
    order_id in (
      select id from orders where user_id = auth.uid()
    )
  );

-- Users can insert items to their own orders
create policy "order_items_are_insertable_to_own_orders"
  on order_items
  for insert
  to authenticated
  with check (
    order_id in (
      select id from orders where user_id = auth.uid()
    )
  );

-- Users can update items in their own orders
create policy "order_items_are_updatable_in_own_orders"
  on order_items
  for update
  to authenticated
  using (
    order_id in (
      select id from orders where user_id = auth.uid()
    )
  )
  with check (
    order_id in (
      select id from orders where user_id = auth.uid()
    )
  );

-- Users can delete items from their own orders
create policy "order_items_are_deletable_from_own_orders"
  on order_items
  for delete
  to authenticated
  using (
    order_id in (
      select id from orders where user_id = auth.uid()
    )
  );

-- Create indexes
create index order_items_order_id_idx on order_items(order_id);
create index order_items_product_id_idx on order_items(product_id);
