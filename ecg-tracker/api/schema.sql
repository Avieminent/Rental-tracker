-- ============================================================
-- ECG Operations Platform — database schema (PostgreSQL)
--
-- Design: a generic record store. Every module (rentals, concierge,
-- census, rehospitalization, AR, staffing, roster, audit reviews)
-- stores its rows as JSON in `record`, keyed by module + collection +
-- facility. This means new modules need NO schema change — matching
-- the config-driven front end. Per-facility access is enforced in the
-- API on every request.
-- ============================================================

create extension if not exists "pgcrypto";

create table facility (
  id              uuid primary key default gen_random_uuid(),
  name            text not null unique,
  tagline         text,
  location        text,
  sort_order      int default 0,
  -- roster / profile metadata
  beds            text,
  rdo             text,
  rdcs            text,
  nha             text,
  don             text,
  survey          text,
  rating_overall  int,
  rating_staffing int,
  total_staff     text,
  open_roles      text
);

create table app_user (
  id            uuid primary key default gen_random_uuid(),
  email         text not null unique,
  password_hash text not null,
  role          text not null check (role in ('admin','corporate','facility')),
  facility_id   uuid references facility(id) on delete cascade,
  created_at    timestamptz not null default now(),
  constraint role_scope check (
    (role in ('admin','corporate') and facility_id is null) or
    (role = 'facility'             and facility_id is not null)
  )
);
-- admin    : sees everything + manages logins + the hidden Activity log
-- corporate: sees everything, no login manager
-- facility : pinned to one facility

-- Password reset links (only the SHA-256 hash of the emailed token is stored).
create table password_reset (
  token_hash text primary key,
  user_id    uuid not null references app_user(id) on delete cascade,
  expires_at timestamptz not null,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);

-- One row per record across every module.
--   module     e.g. 'rentals','concierge','reviews','census','rehosp','ar','staffing','roster'
--   collection sub-bucket: a tab id, or 'items'/'residents'/'staff'/program name
--   data       the row payload (the shape the front end uses)
create table record (
  id          uuid primary key default gen_random_uuid(),
  facility_id uuid not null references facility(id) on delete cascade,
  module      text not null,
  collection  text not null,
  data        jsonb not null default '{}',
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index on record (module, collection);
create index on record (facility_id);
create index on record (facility_id, module, collection);

-- Lightweight HIPAA-oriented audit trail of writes (and bootstrap reads).
create table access_log (
  id          bigserial primary key,
  at          timestamptz not null default now(),
  user_email  text,
  action      text,        -- 'login','bootstrap','create','update','delete'
  module      text,
  facility_id uuid,
  record_id   uuid
);

create or replace function touch_updated() returns trigger as $$
begin new.updated_at = now(); return new; end; $$ language plpgsql;
create trigger trg_record_touch before update on record
  for each row execute function touch_updated();
