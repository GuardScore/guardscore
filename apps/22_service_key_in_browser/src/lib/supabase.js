import { createClient } from '@supabase/supabase-js';
// Fake test keys: the anon key is fine in the browser, the service-role key is not.
export const supabase = createClient('https://exampleref0000000000.supabase.co', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4YW1wbGVyZWYwMDAwMDAwMDAwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0.ZmFrZXNpZ25hdHVyZWZvcnRlc3RzMDAwMDAwMDAwMDA');
export const admin = createClient('https://exampleref0000000000.supabase.co', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4YW1wbGVyZWYwMDAwMDAwMDAwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.ZmFrZXNpZ25hdHVyZWZvcnRlc3RzMDAwMDAwMDAwMDA');
