-- ============================================================
-- Eminent Care Group — Equipment Rental Tracker
-- PostgreSQL schema (tables + calculation views)
--
-- This holds the equipment your SNFs track outside PCC. All of
-- the rent-vs-buy math (days out, rental-to-date, break-even,
-- recommendation) lives in the v_rental_item view so every
-- client sees identical numbers.
-- ============================================================

create extension if not exists "pgcrypto";   -- gen_random_uuid()

-- ---------- Facilities ----------
create table facility (
  id          uuid primary key default gen_random_uuid(),
  name        text not null unique,
  tagline     text not null default 'Rehabilitation & Nursing Center',
  location    text,
  sort_order  int  not null default 0,
  created_at  timestamptz not null default now()
);

-- ---------- Rental items (one row per piece of equipment) ----------
create table rental_item (
  id             uuid primary key default gen_random_uuid(),
  facility_id    uuid not null references facility(id) on delete cascade,
  resident       text,
  room           text,
  status         text not null default 'Active'
                   check (status in ('Active','Pending Order','Discontinued')),
  equipment      text not null,
  category       text not null default 'Mattress/Bed'
                   check (category in ('Mattress/Bed','Oxygen/Respiratory','Wound Care','Mobility','Other')),
  vendor         text,
  start_date     date,
  daily_rate     numeric(10,2),
  monthly_rate   numeric(10,2),
  purchase_price numeric(10,2),
  comments       text,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index on rental_item (facility_id);
create index on rental_item (category);

-- keep updated_at current on edits
create or replace function set_updated_at() returns trigger as $$
begin new.updated_at = now(); return new; end;
$$ language plpgsql;

create trigger trg_rental_item_updated
  before update on rental_item
  for each row execute function set_updated_at();

-- ---------- Users & access control ----------
-- Three roles, scoped in the API on every request (see server.js):
--   'admin'     — sees/edits every facility + portfolio, AND manages logins
--   'corporate' — sees/edits every facility + portfolio (no login manager)
--   'facility'  — pinned to one facility_id; only that facility's rows
-- 'admin' and 'corporate' have no facility_id (they span all facilities);
-- 'facility' must have one.
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
create index on app_user (facility_id);

-- ---------- Audit log (append-only) ----------
-- One row per security-relevant action: logins, and every create/edit/delete.
-- The app only ever INSERTs here. user_email/role are denormalized so a line
-- stays readable even if the user is later removed.
create table audit_log (
  id          bigint generated always as identity primary key,
  at          timestamptz not null default now(),
  user_id     uuid references app_user(id) on delete set null,
  user_email  text,
  role        text,
  action      text not null,   -- login, login_failed, item.create, item.update, ...
  facility_id uuid,
  detail      text
);
create index on audit_log (at desc);

-- ---------- Password reset links ----------
-- One row per reset request. We store only the SHA-256 hash of the emailed
-- token (never the token itself), with a 1-hour expiry and single-use flag.
create table password_reset (
  token_hash text primary key,
  user_id    uuid not null references app_user(id) on delete cascade,
  expires_at timestamptz not null,
  used_at    timestamptz,
  created_at timestamptz not null default now()
);
create index on password_reset (user_id);

-- ============================================================
-- Calculation view: every derived number for an item.
--   monthly_effective : monthly_rate, else daily_rate * 30
--   days_out          : whole days since start_date (>= 0)
--   rental_to_date    : monthly_effective * days_out / 30
--   break_even_months : purchase_price / monthly_effective
--   recommendation    : buy | consider | rent | none
-- ============================================================
create or replace view v_rental_item as
with c as (
  select
    i.*,
    coalesce(i.monthly_rate, i.daily_rate * 30)                       as monthly_effective,
    case when i.start_date is null then null
         else greatest(0, (current_date - i.start_date)) end          as days_out
  from rental_item i
)
select
  c.*,
  case when c.monthly_effective is null or c.days_out is null then null
       else round(c.monthly_effective * c.days_out / 30.0, 2)
  end                                                                 as rental_to_date,
  case when c.purchase_price is null
            or coalesce(c.monthly_effective, 0) = 0 then null
       else round(c.purchase_price / c.monthly_effective, 2)
  end                                                                 as break_even_months,
  case
    when c.purchase_price is not null and c.monthly_effective is not null then
      case
        when c.monthly_effective * coalesce(c.days_out, 0) / 30.0 >= c.purchase_price
             then 'buy'
        when c.purchase_price / c.monthly_effective <= 3
             then 'consider'
        else 'rent'
      end
    when c.monthly_effective is not null then 'rent'
    else 'none'
  end                                                                 as recommendation
from c;

-- ============================================================
-- Portfolio summary: one row per facility (the corporate dash).
-- ============================================================
create or replace view v_portfolio_summary as
select
  f.id,
  f.name,
  f.sort_order,
  count(v.id)                                                   as items,
  coalesce(sum(v.daily_rate), 0)                                as daily_total,
  coalesce(sum(v.monthly_effective), 0)                         as monthly_total,
  coalesce(sum(v.rental_to_date), 0)                            as rental_to_date_total,
  coalesce(sum(v.purchase_price), 0)                            as purchase_value,
  coalesce(sum(v.monthly_effective), 0) * 12                    as annualized,
  count(*) filter (where v.recommendation in ('buy','consider')) as to_review
from facility f
left join v_rental_item v on v.facility_id = f.id
group by f.id, f.name, f.sort_order
order by f.sort_order, f.name;
