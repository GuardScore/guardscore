-- Enable extensions
create extension if not exists "uuid-ossp";

-- Teams table
create table teams (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  description text,
  owner_id uuid not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Team members join table (with role-based access)
create table team_members (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null,
  role text not null check (role in ('owner', 'admin', 'member')),
  joined_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Projects table
create table projects (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text not null default 'active' check (status in ('active', 'archived', 'completed')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Tasks table
create table tasks (
  id uuid primary key default uuid_generate_v4(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'in_review', 'done')),
  priority text not null default 'medium' check (priority in ('low', 'medium', 'high', 'urgent')),
  assigned_to uuid,
  due_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  created_by uuid not null
);

-- Indexes for performance
create index idx_teams_owner_id on teams(owner_id);
create index idx_team_members_team_id on team_members(team_id);
create index idx_team_members_user_id on team_members(user_id);
create index idx_projects_team_id on projects(team_id);
create index idx_tasks_project_id on tasks(project_id);
create index idx_tasks_assigned_to on tasks(assigned_to);

-- Row Level Security Policies

-- Teams: Users can view teams they're members of
alter table teams enable row level security;

create policy "Users can view teams they belong to"
  on teams for select
  using (
    auth.uid() in (
      select user_id from team_members where team_id = teams.id
    )
    or owner_id = auth.uid()
  );

create policy "Team owner can update their team"
  on teams for update
  using (owner_id = auth.uid());

create policy "Team owner can delete their team"
  on teams for delete
  using (owner_id = auth.uid());

create policy "Authenticated users can create teams"
  on teams for insert
  with check (auth.role() = 'authenticated' and owner_id = auth.uid());

-- Team Members: Control access to team membership
alter table team_members enable row level security;

create policy "Team members can view team membership"
  on team_members for select
  using (
    team_id in (
      select id from teams
      where owner_id = auth.uid()
      or id in (select team_id from team_members where user_id = auth.uid())
    )
  );

create policy "Team owner and admins can manage team members"
  on team_members for insert
  with check (
    exists (
      select 1 from teams where id = team_id and owner_id = auth.uid()
    )
    or exists (
      select 1 from team_members
      where team_id = team_members.team_id
      and user_id = auth.uid()
      and role in ('owner', 'admin')
    )
  );

create policy "Team owner and admins can remove team members"
  on team_members for delete
  using (
    exists (
      select 1 from teams where id = team_id and owner_id = auth.uid()
    )
    or exists (
      select 1 from team_members tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

-- Projects: Users can view/manage projects in their teams
alter table projects enable row level security;

create policy "Team members can view projects"
  on projects for select
  using (
    team_id in (
      select id from teams
      where owner_id = auth.uid()
      or id in (select team_id from team_members where user_id = auth.uid())
    )
  );

create policy "Team members can create projects"
  on projects for insert
  with check (
    team_id in (
      select id from teams
      where owner_id = auth.uid()
      or id in (select team_id from team_members where user_id = auth.uid())
    )
  );

create policy "Team members can update projects"
  on projects for update
  using (
    team_id in (
      select id from teams
      where owner_id = auth.uid()
      or id in (select team_id from team_members where user_id = auth.uid())
    )
  );

create policy "Team owner can delete projects"
  on projects for delete
  using (
    team_id in (
      select id from teams where owner_id = auth.uid()
    )
  );

-- Tasks: Users can view/manage tasks in their project's team
alter table tasks enable row level security;

create policy "Team members can view tasks"
  on tasks for select
  using (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams
        where owner_id = auth.uid()
        or id in (select team_id from team_members where user_id = auth.uid())
      )
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams
        where owner_id = auth.uid()
        or id in (select team_id from team_members where user_id = auth.uid())
      )
    )
  );

create policy "Team members can update tasks"
  on tasks for update
  using (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams
        where owner_id = auth.uid()
        or id in (select team_id from team_members where user_id = auth.uid())
      )
    )
  );

create policy "Team owner can delete tasks"
  on tasks for delete
  using (
    project_id in (
      select id from projects
      where team_id in (
        select id from teams where owner_id = auth.uid()
      )
    )
  );
