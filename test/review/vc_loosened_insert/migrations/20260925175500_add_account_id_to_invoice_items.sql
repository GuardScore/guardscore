-- Add account_id to invoice_items for direct RLS checking
-- This allows the security checker to test access control properly

alter table invoice_items add column account_id uuid;

-- Add foreign key constraint
alter table invoice_items
add constraint fk_invoice_items_account
foreign key (account_id) references accounts(id) on delete cascade;

-- Create a trigger to automatically set account_id from the invoice
create or replace function set_invoice_item_account_id()
returns trigger as $$
begin
  select account_id into new.account_id from invoices where id = new.invoice_id;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_set_invoice_item_account_id on invoice_items;
create trigger trigger_set_invoice_item_account_id
before insert on invoice_items
for each row
execute function set_invoice_item_account_id();

-- Update existing rows
update invoice_items
set account_id = (select account_id from invoices where id = invoice_items.invoice_id)
where account_id is null;

-- Update RLS policies for invoice_items to use direct account_id check
drop policy if exists "Users can view invoice items" on invoice_items;
drop policy if exists "Users can create invoice items" on invoice_items;
drop policy if exists "Users can update invoice items" on invoice_items;
drop policy if exists "Users can delete invoice items" on invoice_items;
drop policy if exists "invoice_items_read" on invoice_items;

create policy "Users can view invoice items"
  on invoice_items for select
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can create invoice items"
  on invoice_items for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can update invoice items"
  on invoice_items for update
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ))
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can delete invoice items"
  on invoice_items for delete
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

-- Add index for better performance
create index idx_invoice_items_account_id on invoice_items(account_id);
