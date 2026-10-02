-- Create teams table
CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT,
  owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create team members table
CREATE TABLE team_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(team_id, user_id)
);

-- Create projects table
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived', 'completed')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create tasks table
CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'in_progress', 'review', 'done')),
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  assigned_to UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  due_date DATE,
  created_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create task comments table
CREATE TABLE task_comments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes
CREATE INDEX idx_team_members_team_id ON team_members(team_id);
CREATE INDEX idx_team_members_user_id ON team_members(user_id);
CREATE INDEX idx_projects_team_id ON projects(team_id);
CREATE INDEX idx_tasks_project_id ON tasks(project_id);
CREATE INDEX idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX idx_task_comments_task_id ON task_comments(task_id);

-- Enable RLS
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE task_comments ENABLE ROW LEVEL SECURITY;

-- Teams: Users can see teams they're members of or own
CREATE POLICY "Users can view their teams"
  ON teams FOR SELECT
  USING (
    owner_id = auth.uid() OR
    EXISTS (SELECT 1 FROM team_members WHERE team_id = teams.id AND user_id = auth.uid())
  );

CREATE POLICY "Users can create teams"
  ON teams FOR INSERT
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Team owners can update their teams"
  ON teams FOR UPDATE
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

-- Team members: Only team members and owners can see/manage
CREATE POLICY "Users can view team members of their teams"
  ON team_members FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM teams
      WHERE teams.id = team_members.team_id AND
      (teams.owner_id = auth.uid() OR auth.uid() = team_members.user_id OR
       EXISTS (SELECT 1 FROM team_members tm WHERE tm.team_id = teams.id AND tm.user_id = auth.uid()))
    )
  );

CREATE POLICY "Team owners can manage team members"
  ON team_members FOR INSERT
  WITH CHECK (
    EXISTS (SELECT 1 FROM teams WHERE teams.id = team_members.team_id AND teams.owner_id = auth.uid())
  );

CREATE POLICY "Team owners can remove members"
  ON team_members FOR DELETE
  USING (
    EXISTS (SELECT 1 FROM teams WHERE teams.id = team_members.team_id AND teams.owner_id = auth.uid())
  );

-- Projects: Team members can view, team owners/admins can manage
CREATE POLICY "Team members can view projects"
  ON projects FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
    ) OR
    EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
  );

CREATE POLICY "Team members can create projects"
  ON projects FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
    ) OR
    EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
  );

CREATE POLICY "Team members can update projects"
  ON projects FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
    ) OR
    EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
  );

-- Tasks: Team members can view, assignee and creators can manage
CREATE POLICY "Team members can view tasks"
  ON tasks FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM projects
      WHERE projects.id = tasks.project_id AND (
        EXISTS (
          SELECT 1 FROM team_members
          WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
        ) OR
        EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
      )
    )
  );

CREATE POLICY "Team members can create tasks"
  ON tasks FOR INSERT
  WITH CHECK (
    created_by = auth.uid() AND
    EXISTS (
      SELECT 1 FROM projects
      WHERE projects.id = tasks.project_id AND (
        EXISTS (
          SELECT 1 FROM team_members
          WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
        ) OR
        EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
      )
    )
  );

CREATE POLICY "Assignee and creator can update tasks"
  ON tasks FOR UPDATE
  USING (
    assigned_to = auth.uid() OR
    created_by = auth.uid() OR
    EXISTS (
      SELECT 1 FROM projects p
      INNER JOIN teams t ON p.team_id = t.id
      WHERE p.id = tasks.project_id AND t.owner_id = auth.uid()
    )
  );

-- Task comments: Team members can view and add comments
CREATE POLICY "Team members can view comments"
  ON task_comments FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM tasks
      WHERE tasks.id = task_comments.task_id AND
      EXISTS (
        SELECT 1 FROM projects
        WHERE projects.id = tasks.project_id AND (
          EXISTS (
            SELECT 1 FROM team_members
            WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
          ) OR
          EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
        )
      )
    )
  );

CREATE POLICY "Team members can add comments"
  ON task_comments FOR INSERT
  WITH CHECK (
    user_id = auth.uid() AND
    EXISTS (
      SELECT 1 FROM tasks
      WHERE tasks.id = task_comments.task_id AND
      EXISTS (
        SELECT 1 FROM projects
        WHERE projects.id = tasks.project_id AND (
          EXISTS (
            SELECT 1 FROM team_members
            WHERE team_members.team_id = projects.team_id AND team_members.user_id = auth.uid()
          ) OR
          EXISTS (SELECT 1 FROM teams WHERE teams.id = projects.team_id AND teams.owner_id = auth.uid())
        )
      )
    )
  );

CREATE POLICY "Users can delete their own comments"
  ON task_comments FOR DELETE
  USING (user_id = auth.uid());
