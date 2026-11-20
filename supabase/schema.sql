-- PhishGuard database schema. Run once in the Supabase SQL editor.
-- The API connects with the service-role key (SUPABASE_KEY), which bypasses
-- row-level security. RLS is enabled with no policies so the public anon key
-- can read or write nothing.

create table if not exists public.api_keys (
  id          bigint generated always as identity primary key,
  email       text not null unique,
  api_key     text not null unique,
  requests    integer not null default 0,
  created_at  timestamptz not null default now()
);

create table if not exists public.analytics (
  id          bigint generated always as identity primary key,
  api_key     text references public.api_keys (api_key) on delete cascade,
  url         text not null,
  risk_score  real not null,
  is_safe     boolean not null,
  created_at  timestamptz not null default now()
);

create index if not exists analytics_key_time on public.analytics (api_key, created_at desc);

alter table public.api_keys enable row level security;
alter table public.analytics enable row level security;
