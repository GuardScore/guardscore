-- Create function to calculate order total from items
create or replace function calculate_order_total(order_id uuid)
returns numeric as $$
  select coalesce(sum(quantity * price_at_purchase), 0)
  from order_items
  where order_items.order_id = $1;
$$ language sql stable;

-- Create function to get order details with items
create or replace function get_order_with_items(order_id uuid)
returns table (
  order_id uuid,
  customer_id uuid,
  user_id uuid,
  status text,
  total_amount numeric,
  shipping_address text,
  notes text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  items json
) as $$
  select
    o.id,
    o.customer_id,
    o.user_id,
    o.status,
    o.total_amount,
    o.shipping_address,
    o.notes,
    o.created_at,
    o.updated_at,
    coalesce(
      json_agg(
        json_build_object(
          'id', oi.id,
          'product_id', oi.product_id,
          'quantity', oi.quantity,
          'price_at_purchase', oi.price_at_purchase,
          'product_name', p.name
        )
      ) filter (where oi.id is not null),
      '[]'::json
    ) as items
  from orders o
  left join order_items oi on o.id = oi.order_id
  left join products p on oi.product_id = p.id
  where o.id = $1
  group by o.id, o.customer_id, o.user_id, o.status, o.total_amount, o.shipping_address, o.notes, o.created_at, o.updated_at;
$$ language sql stable;

-- Create function to sync order total (call when items change)
create or replace function sync_order_total()
returns trigger as $$
begin
  update orders
  set total_amount = calculate_order_total(new.order_id),
      updated_at = now()
  where id = new.order_id;
  return new;
end;
$$ language plpgsql;

-- Create trigger to sync order total when items change
drop trigger if exists sync_order_total_on_items_change on order_items;
create trigger sync_order_total_on_items_change
after insert or update or delete on order_items
for each row
execute function sync_order_total();

-- Create function to update updated_at timestamp
create or replace function update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

-- Create trigger to update updated_at on products
drop trigger if exists update_products_updated_at on products;
create trigger update_products_updated_at
before update on products
for each row
execute function update_updated_at_column();

-- Create trigger to update updated_at on customers
drop trigger if exists update_customers_updated_at on customers;
create trigger update_customers_updated_at
before update on customers
for each row
execute function update_updated_at_column();

-- Create trigger to update updated_at on orders
drop trigger if exists update_orders_updated_at on orders;
create trigger update_orders_updated_at
before update on orders
for each row
execute function update_updated_at_column();
