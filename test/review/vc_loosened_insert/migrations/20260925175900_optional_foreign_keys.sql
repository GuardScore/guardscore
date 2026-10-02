-- Make invoice_items.invoice_id optional to allow testing without full invoice hierarchy
alter table invoice_items drop constraint if exists invoice_items_invoice_id_fkey;
alter table invoice_items add constraint invoice_items_invoice_id_fkey
  foreign key (invoice_id) references invoices(id) on delete set null;

-- Update RLS policies to allow viewing/creating invoice_items even without invoice
drop policy if exists "Users can view invoice items" on invoice_items;
create policy "Users can view invoice items"
  on invoice_items for select
  using (
    auth.uid() is not null and (
      invoice_id is null or
      account_id in (select id from accounts where user_id = auth.uid())
    )
  );

drop policy if exists "Users can create invoice items" on invoice_items;
create policy "Users can create invoice items"
  on invoice_items for insert
  to authenticated
  with check (
    invoice_id is null or
    account_id in (select id from accounts where user_id = auth.uid())
  );

drop policy if exists "Users can update invoice items" on invoice_items;
create policy "Users can update invoice items"
  on invoice_items for update
  using (
    account_id in (select id from accounts where user_id = auth.uid())
  )
  with check (
    account_id in (select id from accounts where user_id = auth.uid())
  );

drop policy if exists "Users can delete invoice items" on invoice_items;
create policy "Users can delete invoice items"
  on invoice_items for delete
  using (
    account_id in (select id from accounts where user_id = auth.uid())
  );
