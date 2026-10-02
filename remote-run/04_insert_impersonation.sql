-- verified-changes remote gauntlet: 04_insert_impersonation

select vc.reset();

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  amount_cents int not null
);
alter table public.orders enable row level security;
create policy "own read" on public.orders for select to authenticated using (user_id = auth.uid());
-- Bug: any logged-in user may insert, with any user_id.
create policy "insert" on public.orders for insert to authenticated with check (true);
create policy "own update" on public.orders for update to authenticated using (user_id = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.orders (user_id, amount_cents) values ('00000000-0000-4000-8000-00000000000a', 1999), ('00000000-0000-4000-8000-00000000000b', 4999);


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'orders.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."orders"', 'count'),
  (1, 'orders.anon.update', 'anon', '{"role":"anon"}', 'update public."orders" set "id" = "id" where true', 'affected'),
  (2, 'orders.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."orders" where true', 'affected'),
  (3, 'orders.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."orders" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'orders.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."orders" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'orders.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."orders" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'orders.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."orders" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'orders.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."orders" set "amount_cents" = (jsonb_populate_record(null::public."orders", ''{"amount_cents":1999}''::jsonb))."amount_cents"', 'affected'),
  (8, 'orders.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."orders"', 'affected'),
  (9, 'orders.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."orders" ("user_id", "amount_cents") select "user_id", "amount_cents" from jsonb_populate_record(null::public."orders", ''{"user_id":"00000000-0000-4000-8000-00000000000a","amount_cents":1999}''::jsonb)', 'affected'),
  (10, 'orders.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."orders" ("user_id", "amount_cents") select "user_id", "amount_cents" from jsonb_populate_record(null::public."orders", ''{"user_id":"00000000-0000-4000-8000-00000000000a","amount_cents":1999}''::jsonb)', 'affected'),
  (11, 'orders.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."orders" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'orders.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."orders" ("user_id", "amount_cents") select "user_id", "amount_cents" from jsonb_populate_record(null::public."orders", ''{"user_id":"00000000-0000-4000-8000-00000000000a","amount_cents":1999}''::jsonb)', 'affected'),
  (13, 'orders.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."orders" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected')
) as v(ord, id, role, claims, q, judge);