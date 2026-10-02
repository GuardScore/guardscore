-- Create teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  created_by uuid not null references auth.users(id) on delete cascade
);

-- Create team_members table (junction table for users and teams)
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  joined_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Create projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text not null default 'active' check (status in ('active', 'archived', 'completed')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  created_by uuid not null references auth.users(id) on delete cascade
);

-- Create tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'review', 'done')),
  priority text not null default 'medium' check (priority in ('low', 'medium', 'high')),
  assigned_to uuid references auth.users(id) on delete set null,
  due_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  created_by uuid not null references auth.users(id) on delete cascade
);

-- Create indexes for better query performance
create index teams_created_by_idx on teams(created_by);
create index team_members_team_id_idx on team_members(team_id);
create index team_members_user_id_idx on team_members(user_id);
create index projects_team_id_idx on projects(team_id);
create index projects_created_by_idx on projects(created_by);
create index tasks_project_id_idx on tasks(project_id);
create index tasks_assigned_to_idx on tasks(assigned_to);
create index tasks_created_by_idx on tasks(created_by);

-- Enable RLS on all tables
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;

-- Teams policies: users can see and manage teams they're members of
create policy "Users can view their teams"
  on teams for select
  using (
    id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Users can update their teams"
  on teams for update
  using (
    id in (
      select team_id from team_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

create policy "Users can delete their teams (owner only)"
  on teams for delete
  using (
    id in (
      select team_id from team_members
      where user_id = auth.uid() and role = 'owner'
    )
  );

create policy "Users can create teams"
  on teams for insert
  with check (created_by = auth.uid());

-- Team members policies
create policy "Users can view team members of their teams"
  on team_members for select
  using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Admins can add team members"
  on team_members for insert
  with check (
    team_id in (
      select team_id from team_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

create policy "Admins can update team members"
  on team_members for update
  using (
    team_id in (
      select team_id from team_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

create policy "Admins can remove team members"
  on team_members for delete
  using (
    team_id in (
      select team_id from team_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

-- Projects policies: users can see projects in their teams
create policy "Users can view projects in their teams"
  on projects for select
  using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Team members can create projects"
  on projects for insert
  with check (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Team members can update projects in their teams"
  on projects for update
  using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Admins can delete projects"
  on projects for delete
  using (
    team_id in (
      select team_id from team_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

-- Tasks policies: users can see tasks in projects of their teams
create policy "Users can view tasks in their projects"
  on tasks for select
  using (
    project_id in (
      select id from projects
      where team_id in (
        select team_id from team_members where user_id = auth.uid()
      )
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    project_id in (
      select id from projects
      where team_id in (
        select team_id from team_members where user_id = auth.uid()
      )
    )
  );

create policy "Users can update tasks they created or are assigned to"
  on tasks for update
  using (
    (created_by = auth.uid() or assigned_to = auth.uid())
    or
    project_id in (
      select id from projects
      where team_id in (
        select team_id from team_members
        where user_id = auth.uid() and role in ('owner', 'admin')
      )
    )
  );

create policy "Admins can delete tasks"
  on tasks for delete
  using (
    project_id in (
      select id from projects
      where team_id in (
        select team_id from team_members
        where user_id = auth.uid() and role in ('owner', 'admin')
      )
    )
  );
