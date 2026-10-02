-- Agent-style store, intended secure: public catalog, private orders, staff role.
create type public.user_role as enum ('customer', 'staff', 'admin');
create type public.order_status as enum ('pending', 'paid', 'shipped', 'delivered', 'cancelled');
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text, full_name text,
  role public.user_role not null default 'customer',
  created_at timestamptz default now()
);
create table public.categories (id serial primary key, name text not null unique, slug text not null unique);
create table public.products (
  id uuid primary key default gen_random_uuid(),
  category_id int references public.categories,
  name text not null, slug text not null unique, description text,
  price_cents integer not null check (price_cents >= 0), stock integer not null default 0,
  is_active boolean not null default true, created_at timestamptz default now()
);
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  status public.order_status not null default 'pending',
  total_cents integer not null default 0, shipping_address jsonb,
  created_at timestamptz default now()
);
create table public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders on delete cascade,
  product_id uuid not null references public.products,
  quantity int not null check (quantity > 0), unit_price_cents int not null
);
create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  rating int not null check (rating between 1 and 5), body text,
  created_at timestamptz default now(),
  unique (product_id, user_id)
);
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin insert into public.profiles (id, email) values (new.id, new.email); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role in ('staff', 'admin'));
$$;
-- Users can't change their own role.
create or replace function public.prevent_role_change() returns trigger language plpgsql as $$
begin
  if new.role <> old.role and not public.is_staff() then raise exception 'You cannot change your role'; end if;
  return new;
end $$;
create trigger prevent_role_change before update on public.profiles for each row execute function public.prevent_role_change();

alter table public.profiles enable row level security;
alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.reviews enable row level security;
create policy "profiles self" on public.profiles for select using (auth.uid() = id or public.is_staff());
create policy "profiles update self" on public.profiles for update using (auth.uid() = id);
create policy "categories public" on public.categories for select using (true);
create policy "categories staff" on public.categories for all using (public.is_staff()) with check (public.is_staff());
create policy "products public" on public.products for select using (true);
create policy "products staff" on public.products for all using (public.is_staff()) with check (public.is_staff());
create policy "orders own" on public.orders for select using (auth.uid() = customer_id or public.is_staff());
create policy "orders create" on public.orders for insert with check (auth.uid() = customer_id);
create policy "orders staff update" on public.orders for update using (public.is_staff());
create policy "items own" on public.order_items for select using (exists (select 1 from public.orders o where o.id = order_id and (o.customer_id = auth.uid() or public.is_staff())));
create policy "items create" on public.order_items for insert with check (exists (select 1 from public.orders o where o.id = order_id and o.customer_id = auth.uid()));
create policy "reviews public" on public.reviews for select using (true);
create policy "reviews write own" on public.reviews for insert to authenticated with check (auth.uid() = user_id);
create policy "reviews update own" on public.reviews for update to authenticated using (auth.uid() = user_id);
create policy "reviews delete own" on public.reviews for delete to authenticated using (auth.uid() = user_id);
