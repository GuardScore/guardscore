-- Supabase compatibility shim for local verification.
-- Reproduces the parts of Supabase that access-control depends on:
-- the anon / authenticated / service_role roles, default grants on the
-- public schema, auth.uid() / auth.jwt() backed by per-request JWT claims,
-- and the storage.objects table with RLS enabled.

create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
-- Platform roles migrations grant to (auth hooks, storage, realtime, dashboard).
create role supabase_admin nologin;
create role supabase_auth_admin nologin noinherit;
create role supabase_storage_admin nologin noinherit;
create role supabase_realtime_admin nologin noinherit;
create role authenticator nologin noinherit;
create role dashboard_user nologin;
create role pgbouncer nologin;

-- auth schema -------------------------------------------------------------
create schema auth;
grant usage on schema auth to anon, authenticated, service_role;

create table auth.users (
  id uuid primary key,
  aud text default 'authenticated',
  role text default 'authenticated',
  email text,
  phone text,
  email_confirmed_at timestamptz default now(),
  raw_user_meta_data jsonb default '{}'::jsonb,
  raw_app_meta_data jsonb default '{}'::jsonb,
  is_anonymous boolean default false,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  -- The rest of GoTrue's columns: seed files insert full rows.
  instance_id uuid, encrypted_password text, invited_at timestamptz, confirmation_token text, confirmation_sent_at timestamptz,
  recovery_token text, recovery_sent_at timestamptz, email_change_token_new text, email_change text, email_change_sent_at timestamptz,
  last_sign_in_at timestamptz, is_super_admin boolean, phone_confirmed_at timestamptz, phone_change text, phone_change_token text,
  phone_change_sent_at timestamptz, confirmed_at timestamptz, email_change_token_current text, email_change_confirm_status smallint,
  banned_until timestamptz, reauthentication_token text, reauthentication_sent_at timestamptz, is_sso_user boolean default false, deleted_at timestamptz
);
create table auth.identities (id uuid primary key default gen_random_uuid(), provider_id text, user_id uuid references auth.users(id) on delete cascade,
  identity_data jsonb, provider text, last_sign_in_at timestamptz, created_at timestamptz default now(), updated_at timestamptz default now(), email text);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete cascade, created_at timestamptz default now(),
  updated_at timestamptz, factor_id uuid, aal text, not_after timestamptz, user_agent text, ip inet);
create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete cascade, friendly_name text,
  factor_type text, status text, created_at timestamptz default now(), updated_at timestamptz default now(), secret text, phone text);
create table auth.mfa_challenges (id uuid primary key default gen_random_uuid(), factor_id uuid references auth.mfa_factors(id) on delete cascade,
  created_at timestamptz default now(), verified_at timestamptz, ip_address inet);
create table auth.mfa_amr_claims (id uuid primary key default gen_random_uuid(), session_id uuid references auth.sessions(id) on delete cascade,
  created_at timestamptz default now(), updated_at timestamptz default now(), authentication_method text);
create table auth.refresh_tokens (id bigserial primary key, token text, user_id text, revoked boolean, created_at timestamptz default now(), updated_at timestamptz, parent text, session_id uuid);
create table auth.audit_log_entries (instance_id uuid, id uuid primary key default gen_random_uuid(), payload json, created_at timestamptz default now(), ip_address text default '');
grant select on auth.mfa_factors, auth.sessions, auth.identities to authenticated;
-- Sample users sign up the way real ones do, with the profile fields signup
-- forms send (a signup trigger that copies username into profiles needs one).
create function auth.vc_signup_metadata() returns trigger language plpgsql as $$
declare u text := split_part(coalesce(new.email, new.id::text), '@', 1);
begin
  if new.raw_user_meta_data is null or new.raw_user_meta_data = '{}'::jsonb then
    new.raw_user_meta_data := jsonb_build_object('username', u, 'user_name', u, 'name', initcap(u), 'full_name', initcap(u) || ' Example',
      'display_name', initcap(u), 'first_name', initcap(u), 'last_name', 'Example', 'avatar_url', 'https://example.test/' || u || '.png', 'email', new.email,
      -- A valid adult birthdate/age, so a signup trigger that enforces an age
      -- minimum (16+/18+) lets the sample users through.
      'date_of_birth', '1990-01-01', 'dob', '1990-01-01', 'birthdate', '1990-01-01', 'age', '30');
  end if;
  return new;
end $$;
create trigger aaa_vc_signup_metadata before insert on auth.users for each row execute function auth.vc_signup_metadata();

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;

create function auth.uid() returns uuid language sql stable as $$
  select nullif(auth.jwt() ->> 'sub', '')::uuid
$$;

create function auth.role() returns text language sql stable as $$
  select auth.jwt() ->> 'role'
$$;

create function auth.email() returns text language sql stable as $$
  select auth.jwt() ->> 'email'
$$;

grant execute on all functions in schema auth to anon, authenticated, service_role;

-- public schema: Supabase grants table access to the API roles by default,
-- which is exactly why a table without RLS is readable by anyone.
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;

-- storage schema ------------------------------------------------------------
create schema storage;
grant usage on schema storage to anon, authenticated, service_role;

create table storage.buckets (
  id text primary key,
  name text not null,
  owner uuid,
  owner_id text,
  public boolean default false,
  avif_autodetection boolean default false,
  file_size_limit bigint,
  allowed_mime_types text[],
  type text default 'STANDARD',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets(id),
  name text,
  owner uuid,
  owner_id text,
  metadata jsonb,
  user_metadata jsonb,
  path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  version text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);

-- Resumable (S3-protocol) uploads, which grant/policy migrations reference.
create table storage.s3_multipart_uploads (id text primary key, in_progress_size bigint not null default 0, upload_signature text not null default '',
  bucket_id text not null references storage.buckets(id), key text not null, version text not null default '', owner_id text, created_at timestamptz not null default now(), user_metadata jsonb);
create table storage.s3_multipart_uploads_parts (id uuid primary key default gen_random_uuid(), upload_id text not null references storage.s3_multipart_uploads(id) on delete cascade,
  size bigint not null default 0, part_number int not null, bucket_id text not null references storage.buckets(id), key text not null, etag text not null,
  owner_id text, version text not null, created_at timestamptz not null default now());
alter table storage.s3_multipart_uploads enable row level security;
alter table storage.s3_multipart_uploads_parts enable row level security;

-- Path helpers Supabase ships and agents use in storage policies.
create function storage.foldername(name text) returns text[] language plpgsql immutable as $$
declare _parts text[];
begin
  select string_to_array(name, '/') into _parts;
  return _parts[1:array_length(_parts, 1) - 1];
end $$;
create function storage.filename(name text) returns text language plpgsql immutable as $$
declare _parts text[];
begin
  select string_to_array(name, '/') into _parts;
  return _parts[array_length(_parts, 1)];
end $$;
create function storage.extension(name text) returns text language plpgsql immutable as $$
declare _parts text[]; _filename text;
begin
  select string_to_array(name, '/') into _parts;
  select _parts[array_length(_parts, 1)] into _filename;
  return reverse(split_part(reverse(_filename), '.', 1));
end $$;
-- Storage API operation checks (newer policies): the API sets storage.operation
-- per request; with none set (a direct read by the gauntlet, modelling a file
-- download) any operation counts, so a policy can't hide a leak behind it.
create function storage.allow_any_operation(expected_operations text[]) returns boolean language sql stable as $$
  select coalesce(nullif(current_setting('storage.operation', true), ''), '*') = '*' or current_setting('storage.operation', true) = any(expected_operations)
$$;
create function storage.allow_only_operation(expected_operation text) returns boolean language sql stable as $$
  select coalesce(nullif(current_setting('storage.operation', true), ''), '*') = '*' or current_setting('storage.operation', true) = expected_operation
$$;
create function storage.operation() returns text language sql stable as $$ select current_setting('storage.operation', true) $$;
grant execute on all functions in schema storage to anon, authenticated, service_role;

alter table storage.objects enable row level security;
grant select, insert, update, delete on storage.objects to anon, authenticated, service_role;
grant select on storage.buckets to anon, authenticated, service_role;

-- Supabase blocks direct SQL deletes on storage.objects unless
-- storage.allow_delete_query is 'true'. Its Storage API sets that flag and then
-- deletes under the caller's role, so RLS still decides. The gauntlet sets the
-- flag the same way, to test what the Storage API would let a user delete.
create function storage.protect_delete() returns trigger language plpgsql as $$
begin
  -- Migrations run as the database owner; only API callers go through the Storage API.
  if current_user in ('anon', 'authenticated') and coalesce(current_setting('storage.allow_delete_query', true), 'false') != 'true' then
    raise exception 'Direct deletion from storage tables is not allowed. Use the Storage API instead.'
      using errcode = '42501';
  end if;
  return null;
end $$;
create trigger protect_objects_delete before delete on storage.objects
  for each statement execute function storage.protect_delete();


-- extensions schema: Supabase installs extensions here and puts it on the
-- search path, so migrations call uuid_generate_v4() unqualified.
create schema extensions;
grant usage on schema extensions to anon, authenticated, service_role;
-- Supabase pre-installs these two in every project, so migrations call
-- gen_random_bytes() or uuid_generate_v4() without creating them first.
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;
grant execute on all functions in schema extensions to anon, authenticated, service_role;
select set_config('search_path', '"$user", public, extensions', false);

-- Newer projects ship an event-trigger helper that turns row level security
-- on for new tables; migrations revoke or reference it.
create function public.rls_auto_enable() returns event_trigger language plpgsql as $$ begin end $$;

-- Vault: apps keep their project URL or API keys here and read them in
-- functions through vault.decrypted_secrets.
create schema vault;
create table vault.secrets (id uuid primary key default gen_random_uuid(), name text unique, description text default '', secret text not null,
  key_id uuid, nonce bytea, created_at timestamptz default now(), updated_at timestamptz default now());
create view vault.decrypted_secrets as select id, name, description, secret, secret as decrypted_secret, key_id, nonce, created_at, updated_at from vault.secrets;
create function vault.create_secret(new_secret text, new_name text default null, new_description text default '', new_key_id uuid default null) returns uuid language sql as $$
  insert into vault.secrets (secret, name, description, key_id) values (new_secret, new_name, new_description, new_key_id) returning id
$$;
create function vault.update_secret(secret_id uuid, new_secret text default null, new_name text default null, new_description text default null, new_key_id uuid default null) returns void language sql as $$
  update vault.secrets set secret = coalesce(new_secret, secret), name = coalesce(new_name, name), description = coalesce(new_description, description) where id = secret_id
$$;

-- pgsql-http (the "http" extension): the types and calls, answering 200 with
-- no body and sending nothing.
create domain extensions.http_method as text;
create type extensions.http_header as (field varchar, value varchar);
create type extensions.http_request as (method extensions.http_method, uri varchar, headers extensions.http_header[], content_type varchar, content varchar);
create type extensions.http_response as (status integer, content_type varchar, headers extensions.http_header[], content varchar);
create function extensions.http_header(field varchar, value varchar) returns extensions.http_header language sql immutable as $$ select row(field, value)::extensions.http_header $$;
create function extensions.http(request extensions.http_request) returns extensions.http_response language sql as $$ select row(200, 'application/json', '{}'::extensions.http_header[], '')::extensions.http_response $$;
create function extensions.http_get(uri varchar) returns extensions.http_response language sql as $$ select extensions.http(row('GET', uri, null, null, null)::extensions.http_request) $$;
create function extensions.http_get(uri varchar, data jsonb) returns extensions.http_response language sql as $$ select extensions.http(row('GET', uri, null, null, null)::extensions.http_request) $$;
create function extensions.http_post(uri varchar, content varchar, content_type varchar) returns extensions.http_response language sql as $$ select extensions.http(row('POST', uri, null, content_type, content)::extensions.http_request) $$;
create function extensions.http_post(uri varchar, data jsonb) returns extensions.http_response language sql as $$ select extensions.http(row('POST', uri, null, null, null)::extensions.http_request) $$;
create function extensions.http_delete(uri varchar) returns extensions.http_response language sql as $$ select extensions.http(row('DELETE', uri, null, null, null)::extensions.http_request) $$;
create function extensions.http_put(uri varchar, content varchar, content_type varchar) returns extensions.http_response language sql as $$ select extensions.http(row('PUT', uri, null, content_type, content)::extensions.http_request) $$;
create function extensions.http_patch(uri varchar, content varchar, content_type varchar) returns extensions.http_response language sql as $$ select extensions.http(row('PATCH', uri, null, content_type, content)::extensions.http_request) $$;
grant usage on type extensions.http_request, extensions.http_response, extensions.http_header to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;

-- pg_cron and pg_net: scheduled jobs and HTTP calls from SQL. Jobs are
-- recorded, never run; HTTP calls return a request id and send nothing.
create schema cron;
create table cron.job (jobid bigserial primary key, schedule text, command text, nodename text default 'localhost', nodeport int default 5432,
  database text default 'postgres', username text default 'postgres', active boolean default true, jobname text unique);
create function cron.schedule(job_name text, schedule text, command text) returns bigint language sql as $$
  insert into cron.job (jobname, schedule, command) values (job_name, schedule, command)
  on conflict (jobname) do update set schedule = excluded.schedule, command = excluded.command returning jobid
$$;
create function cron.schedule(schedule text, command text) returns bigint language sql as $$
  insert into cron.job (schedule, command) values (schedule, command) returning jobid
$$;
create function cron.unschedule(job_name text) returns boolean language sql as $$ with d as (delete from cron.job where jobname = job_name returning 1) select exists (select 1 from d) $$;
create function cron.unschedule(job_id bigint) returns boolean language sql as $$ with d as (delete from cron.job where jobid = job_id returning 1) select exists (select 1 from d) $$;
create schema net;
create sequence net.vc_request_id;
create function net.http_post(url text, body jsonb default '{}'::jsonb, params jsonb default '{}'::jsonb, headers jsonb default '{"Content-Type": "application/json"}'::jsonb, timeout_milliseconds int default 5000) returns bigint language sql as $$ select nextval('net.vc_request_id') $$;
create function net.http_get(url text, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb, timeout_milliseconds int default 5000) returns bigint language sql as $$ select nextval('net.vc_request_id') $$;
create function net.http_delete(url text, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb, timeout_milliseconds int default 5000) returns bigint language sql as $$ select nextval('net.vc_request_id') $$;
grant usage on schema net to anon, authenticated, service_role;
grant usage on sequence net.vc_request_id to anon, authenticated, service_role;
grant execute on all functions in schema net to anon, authenticated, service_role;

-- Realtime: migrations often add their tables to this publication, and
-- write policies on realtime.messages for private broadcast channels.
create schema realtime;
grant usage on schema realtime to anon, authenticated, service_role;
create table realtime.messages (
  id bigint generated always as identity,
  topic text not null,
  extension text not null default 'broadcast',
  payload jsonb,
  event text,
  private boolean default false,
  inserted_at timestamp default now(),
  updated_at timestamp default now(),
  primary key (id)
);
alter table realtime.messages enable row level security;
grant select, insert on realtime.messages to anon, authenticated, service_role;
create function realtime.topic() returns text language sql stable as $$ select nullif(current_setting('realtime.topic', true), '') $$;
create function realtime.send(payload jsonb, event text, topic text, private boolean default true) returns void language sql as $$
  insert into realtime.messages (payload, event, topic, private, extension) values (payload, event, topic, private, 'broadcast')
$$;
create function realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text default 'ROW') returns void language plpgsql as $$
begin
  perform realtime.send(jsonb_build_object('operation', operation, 'table', table_name, 'schema', table_schema), event_name, topic_name, true);
end $$;
grant execute on all functions in schema realtime to anon, authenticated, service_role;
-- Realtime: migrations often add their tables to this publication.
create publication supabase_realtime;
