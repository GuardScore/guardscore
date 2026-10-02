# Guard every migration push

Run the check before the migration reaches your real database, and only push if it passes:

    npx verified-changes guard -- supabase db push

Or block git pushes that change supabase/migrations unsafely:

    npx verified-changes hook install

Both exit non-zero with the proof and a proven fix when the change would leak data or lock users out.
