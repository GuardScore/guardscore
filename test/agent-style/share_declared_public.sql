-- Create notes table
CREATE TABLE IF NOT EXISTS notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  title TEXT NOT NULL DEFAULT 'Untitled Note',
  content TEXT DEFAULT '',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create index for faster queries by user
CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);

-- Enable RLS (Row Level Security)
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- Create RLS policies
-- Users can only see their own notes
CREATE POLICY "Users can view their own notes"
  ON notes FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only insert their own notes
CREATE POLICY "Users can insert their own notes"
  ON notes FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can only update their own notes
CREATE POLICY "Users can update their own notes"
  ON notes FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Users can only delete their own notes
CREATE POLICY "Users can delete their own notes"
  ON notes FOR DELETE
  USING (auth.uid() = user_id);
-- Create admins table to track admin users
CREATE TABLE IF NOT EXISTS admins (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_admins_user_id ON admins(user_id);

-- Enable RLS on admins table
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;

-- Only admins can view the admins list
CREATE POLICY "Admins can view admin list"
  ON admins FOR SELECT
  USING (EXISTS(SELECT 1 FROM admins WHERE user_id = auth.uid()));

-- Update notes RLS policies to allow admins to see all notes

-- Add admin policy for SELECT (viewing all notes)
CREATE POLICY "Admins can view all notes"
  ON notes FOR SELECT
  USING (
    auth.uid() = user_id OR
    EXISTS(SELECT 1 FROM admins WHERE user_id = auth.uid())
  );

-- Keep existing policies for users' own notes, but no update needed since
-- the SELECT policy now uses OR which allows admins to view
-- Update policy stays the same - only users can update their own notes
-- (admins can't modify user notes, only view them for moderation)

-- Create a moderation_logs table for audit trail
CREATE TABLE IF NOT EXISTS moderation_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  note_id UUID NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_moderation_logs_admin_id ON moderation_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_moderation_logs_note_id ON moderation_logs(note_id);

-- Enable RLS on moderation_logs
ALTER TABLE moderation_logs ENABLE ROW LEVEL SECURITY;

-- Only admins can view moderation logs
CREATE POLICY "Admins can view moderation logs"
  ON moderation_logs FOR SELECT
  USING (EXISTS(SELECT 1 FROM admins WHERE user_id = auth.uid()));

-- Only admins can create moderation logs
CREATE POLICY "Admins can create moderation logs"
  ON moderation_logs FOR INSERT
  WITH CHECK (
    admin_id = auth.uid() AND
    EXISTS(SELECT 1 FROM admins WHERE user_id = auth.uid())
  );
-- Create public_links table for shareable note links
CREATE TABLE IF NOT EXISTS public_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  note_id UUID NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
  created_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  share_token TEXT NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_public_links_note_id ON public_links(note_id);
CREATE INDEX IF NOT EXISTS idx_public_links_share_token ON public_links(share_token);
CREATE INDEX IF NOT EXISTS idx_public_links_created_by ON public_links(created_by);

-- Enable RLS on public_links
ALTER TABLE public_links ENABLE ROW LEVEL SECURITY;

-- Anyone can view public links (to access shared notes)
CREATE POLICY "Anyone can view public links"
  ON public_links FOR SELECT
  USING (true);

-- Only the creator can insert their own links
CREATE POLICY "Users can create links for their notes"
  ON public_links FOR INSERT
  WITH CHECK (
    created_by = auth.uid() AND
    EXISTS(SELECT 1 FROM notes WHERE id = note_id AND user_id = auth.uid())
  );

-- Only the creator can delete their own links
CREATE POLICY "Users can delete their own links"
  ON public_links FOR DELETE
  USING (created_by = auth.uid());

-- Update notes RLS to allow anonymous users to view shared notes
CREATE POLICY "Anyone can view publicly shared notes"
  ON notes FOR SELECT
  USING (
    auth.uid() = user_id OR
    EXISTS(SELECT 1 FROM admins WHERE user_id = auth.uid()) OR
    EXISTS(SELECT 1 FROM public_links WHERE note_id = id)
  );
