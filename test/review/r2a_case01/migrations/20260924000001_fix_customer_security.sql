-- Drop unsafe update policy
drop policy if exists "users_can_update_own_customer" on public.customers;

-- Only admins can update customers
create policy "admins_can_update_customers" on public.customers
  for update using (auth.jwt() ->> 'role' = 'admin');
