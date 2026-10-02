-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Clients table
create table clients (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  email text,
  phone text,
  address text,
  city text,
  country text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Projects table
create table projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  client_id uuid not null references clients(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'completed', 'paused', 'cancelled')),
  budget decimal(10, 2),
  start_date date,
  end_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoices table
create table invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  project_id uuid not null references projects(id) on delete cascade,
  amount decimal(10, 2) not null,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  invoice_date date default current_date,
  due_date date,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for faster queries
create index clients_user_id_idx on clients(user_id);
create index projects_user_id_idx on projects(user_id);
create index projects_client_id_idx on projects(client_id);
create index invoices_user_id_idx on invoices(user_id);
create index invoices_project_id_idx on invoices(project_id);

-- Enable Row Level Security
alter table clients enable row level security;
alter table projects enable row level security;
alter table invoices enable row level security;

-- Clients RLS policies
create policy "Users can view their own clients"
  on clients for select
  using (auth.uid() = user_id);

create policy "Users can create clients"
  on clients for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own clients"
  on clients for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own clients"
  on clients for delete
  using (auth.uid() = user_id);

-- Projects RLS policies
create policy "Users can view their own projects"
  on projects for select
  using (auth.uid() = user_id);

create policy "Users can create projects"
  on projects for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own projects"
  on projects for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own projects"
  on projects for delete
  using (auth.uid() = user_id);

-- Invoices RLS policies
create policy "Users can view their own invoices"
  on invoices for select
  using (auth.uid() = user_id);

create policy "Users can create invoices"
  on invoices for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own invoices"
  on invoices for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own invoices"
  on invoices for delete
  using (auth.uid() = user_id);
