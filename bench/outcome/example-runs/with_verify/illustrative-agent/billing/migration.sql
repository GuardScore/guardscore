create table public.invoices (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), total_cents int not null);
create table public.staff (user_id uuid primary key references auth.users(id));
alter table public.staff enable row level security;
alter table public.invoices enable row level security;
create policy "own or staff" on public.invoices for select to authenticated
  using (user_id = auth.uid() or exists (select 1 from public.staff s where s.user_id = auth.uid()));
