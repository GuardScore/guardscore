-- Teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Team members (links users to teams with roles)
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  joined_at timestamptz default now(),
  unique(team_id, user_id)
);

-- Projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'done')),
  priority text not null default 'medium' check (priority in ('low', 'medium', 'high')),
  assigned_to uuid references auth.users(id) on delete set null,
  created_by uuid not null references auth.users(id) on delete cascade,
  due_date date,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Indexes for performance
create index idx_team_members_user on team_members(user_id);
create index idx_team_members_team on team_members(team_id);
create index idx_projects_team on projects(team_id);
create index idx_tasks_project on tasks(project_id);
create index idx_tasks_assigned on tasks(assigned_to);
create index idx_tasks_status on tasks(status);

-- Enable RLS
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;

-- RLS Policies for teams
create policy "Users can view teams they're members of"
  on teams for select
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Users can create teams"
  on teams for insert
  with check (auth.uid() = created_by);

create policy "Team admins can update teams"
  on teams for update
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
      and team_members.role = 'admin'
    )
  )
  with check (
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
      and team_members.role = 'admin'
    )
  );

-- RLS Policies for team_members
create policy "Users can view team members of teams they're in"
  on team_members for select
  using (
    exists (
      select 1 from team_members tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
    )
  );

create policy "Team admins can add members"
  on team_members for insert
  with check (
    exists (
      select 1 from team_members
      where team_members.team_id = (select team_id from team_members where id = team_members.id)
      and user_id = auth.uid()
      and role = 'admin'
    )
  );

create policy "Team admins can update members"
  on team_members for update
  using (
    exists (
      select 1 from team_members tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
      and tm.role = 'admin'
    )
  );

-- RLS Policies for projects
create policy "Users can view projects in teams they're in"
  on projects for select
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = projects.team_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can create projects"
  on projects for insert
  with check (
    exists (
      select 1 from team_members
      where team_members.team_id = projects.team_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can update projects"
  on projects for update
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = projects.team_id
      and team_members.user_id = auth.uid()
    )
  );

-- RLS Policies for tasks
create policy "Users can view tasks in projects of teams they're in"
  on tasks for select
  using (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can update tasks"
  on tasks for update
  using (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can delete tasks"
  on tasks for delete
  using (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
  );
