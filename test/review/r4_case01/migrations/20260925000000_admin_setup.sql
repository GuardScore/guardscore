-- This migration shows how to set up an admin user
-- Uncomment the appropriate section to make a user an admin

-- Option 1: Make the first user an admin (useful for development)
-- Replace this SQL in the supabase dashboard:
-- update public.profiles set is_admin = true where id = '<user_id>';

-- Option 2: Create a test admin account (email: admin@example.com, password: admin123)
-- This is only for development - change the password in production!
-- SELECT auth.uid(); to get the user ID, then:
-- update public.profiles set is_admin = true where email = 'admin@example.com';
