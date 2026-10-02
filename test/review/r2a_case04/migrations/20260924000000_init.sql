-- Create teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create team_members table
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  created_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Create projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'archived', 'completed')),
  created_by uuid not null references auth.users(id) on delete set null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text default 'todo' check (status in ('todo', 'in_progress', 'done', 'blocked')),
  priority text default 'medium' check (priority in ('low', 'medium', 'high', 'urgent')),
  assigned_to uuid references auth.users(id) on delete set null,
  due_date date,
  created_by uuid not null references auth.users(id) on delete set null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for performance
create index idx_team_members_user_id on team_members(user_id);
create index idx_team_members_team_id on team_members(team_id);
create index idx_projects_team_id on projects(team_id);
create index idx_tasks_project_id on tasks(project_id);
create index idx_tasks_assigned_to on tasks(assigned_to);

-- Enable RLS
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;

-- Teams RLS policies
-- Users can view teams they are members of
create policy "Users can view their teams"
  on teams for select
  using (exists (
    select 1 from team_members
    where team_members.team_id = teams.id
    and team_members.user_id = auth.uid()
  ));

-- Owners and admins can update teams
create policy "Team owners and admins can update teams"
  on teams for update
  using (exists (
    select 1 from team_members
    where team_members.team_id = teams.id
    and team_members.user_id = auth.uid()
    and team_members.role in ('owner', 'admin')
  ));

-- Owners and admins can delete teams
create policy "Team owners and admins can delete teams"
  on teams for delete
  using (exists (
    select 1 from team_members
    where team_members.team_id = teams.id
    and team_members.user_id = auth.uid()
    and team_members.role = 'owner'
  ));

-- Users can create teams
create policy "Users can create teams"
  on teams for insert
  with check (auth.uid() = created_by);

-- Team members RLS policies
-- Users can view team members in their teams
create policy "Users can view team members"
  on team_members for select
  using (exists (
    select 1 from team_members as tm
    where tm.team_id = team_members.team_id
    and tm.user_id = auth.uid()
  ));

-- Team owners and admins can add members
create policy "Team owners and admins can add members"
  on team_members for insert
  with check (exists (
    select 1 from team_members
    where team_members.team_id = team_members.team_id
    and team_members.user_id = auth.uid()
    and team_members.role in ('owner', 'admin')
  ));

-- Team owners and admins can update members
create policy "Team owners and admins can update members"
  on team_members for update
  using (exists (
    select 1 from team_members as tm
    where tm.team_id = team_members.team_id
    and tm.user_id = auth.uid()
    and tm.role in ('owner', 'admin')
  ));

-- Team owners and admins can remove members
create policy "Team owners and admins can remove members"
  on team_members for delete
  using (exists (
    select 1 from team_members as tm
    where tm.team_id = team_members.team_id
    and tm.user_id = auth.uid()
    and tm.role in ('owner', 'admin')
  ));

-- Projects RLS policies
-- Users can view projects in their teams
create policy "Users can view projects in their teams"
  on projects for select
  using (exists (
    select 1 from team_members
    where team_members.team_id = projects.team_id
    and team_members.user_id = auth.uid()
  ));

-- Team members can create projects
create policy "Team members can create projects"
  on projects for insert
  with check (exists (
    select 1 from team_members
    where team_members.team_id = projects.team_id
    and team_members.user_id = auth.uid()
  ));

-- Team members can update projects
create policy "Team members can update projects"
  on projects for update
  using (exists (
    select 1 from team_members
    where team_members.team_id = projects.team_id
    and team_members.user_id = auth.uid()
  ));

-- Team owners and admins can delete projects
create policy "Team owners and admins can delete projects"
  on projects for delete
  using (exists (
    select 1 from team_members
    where team_members.team_id = projects.team_id
    and team_members.user_id = auth.uid()
    and team_members.role in ('owner', 'admin')
  ));

-- Tasks RLS policies
-- Users can view tasks in projects they have access to
create policy "Users can view tasks in their projects"
  on tasks for select
  using (exists (
    select 1 from projects
    join team_members on team_members.team_id = projects.team_id
    where projects.id = tasks.project_id
    and team_members.user_id = auth.uid()
  ));

-- Team members can create tasks
create policy "Team members can create tasks"
  on tasks for insert
  with check (exists (
    select 1 from projects
    join team_members on team_members.team_id = projects.team_id
    where projects.id = tasks.project_id
    and team_members.user_id = auth.uid()
  ));

-- Team members can update tasks
create policy "Team members can update tasks"
  on tasks for update
  using (exists (
    select 1 from projects
    join team_members on team_members.team_id = projects.team_id
    where projects.id = tasks.project_id
    and team_members.user_id = auth.uid()
  ));

-- Team owners and admins can delete tasks
create policy "Team owners and admins can delete tasks"
  on tasks for delete
  using (exists (
    select 1 from projects
    join team_members on team_members.team_id = projects.team_id
    where projects.id = tasks.project_id
    and team_members.user_id = auth.uid()
    and team_members.role in ('owner', 'admin')
  ));
