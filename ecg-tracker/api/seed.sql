-- ============================================================
-- Seed data — 8 facilities + the live Champion City & Eden items
-- (matches the ECG Rental Tracker workbook).
-- Run after schema.sql.
-- ============================================================

begin;

insert into facility (name, tagline, location, sort_order) values
  ('Champion City', 'Rehabilitation & Nursing Center', 'Pittsburgh, PA',        1),
  ('Eden',          'Center for Nursing and Healing',  'formerly Platinum Ridge', 2),
  ('Highland Park', 'Rehabilitation & Nursing Center', null,                     3),
  ('The Pearl',     'Rehabilitation & Nursing Center', null,                     4),
  ('Aristos',       'Rehabilitation & Nursing Center', null,                     5),
  ('Alpine',        'Rehabilitation & Nursing Center', null,                     6),
  ('Atrium',        'Rehabilitation & Nursing Center', null,                     7),
  ('Aspen Glen',    'Rehabilitation & Nursing Center', null,                     8);

-- Items. Casts on the first row pin the column types; later rows may be null.
insert into rental_item
  (facility_id, resident, room, status, equipment, category,
   start_date, daily_rate, monthly_rate, purchase_price, comments)
select f.id, x.resident, x.room, x.status, x.equipment, x.category,
       x.start_date, x.daily, x.monthly, x.purchase, x.comments
from facility f
join (values
  -- Champion City
  ('Champion City','Susan Nesbitt','420 B','Pending Order','36" air mattress','Mattress/Bed',
     date '2026-04-16', 6::numeric, 180::numeric, 335::numeric, 'Emailed Rena to order on 6/22/26'),
  ('Champion City','Gwen Jackson','2015','Pending Order','36" air mattress','Mattress/Bed',
     date '2026-04-16', 6, 180, 335, 'Emailed Rena to order on 6/22/26'),
  ('Champion City','Debra Hunt','5112A','Pending Order','Scoop Mattress','Mattress/Bed',
     date '2026-03-12', 9, 270, 216, 'Emailed Rena to order on 6/22/26'),
  ('Champion City','Mark Majersky','6016B','Active','BiPAP','Oxygen/Respiratory',
     null, null, null, null, 'Rate / start date TBD'),
  ('Champion City','Richard David','2030A','Active','10 L concentrator','Oxygen/Respiratory',
     null, 0, 90, null, ''),
  ('Champion City','Payne Vincent','','Active','10 L concentrator','Oxygen/Respiratory',
     null, 0, 90, null, 'Confirm room #'),
  ('Champion City','Andrea Boyd','5115A','Active','5 L concentrator','Oxygen/Respiratory',
     null, 0, null, null, 'Confirm monthly rate'),
  -- Eden
  ('Eden','Gent, Dana','106A','Active','Bed Frame - Zenith 7200','Mattress/Bed',
     date '2026-05-19', 8, 240, 977, ''),
  ('Eden','Gent, Dana','106A','Active','Reduce Max Preventative Mattress - 42"','Mattress/Bed',
     date '2026-05-19', 2.5, 75, 218, ''),
  ('Eden','Niki Dickey','111B','Active','Bed Frame - Zenith - 42" x 80"','Mattress/Bed',
     date '2026-06-10', 8, 240, 977, ''),
  ('Eden','Niki Dickey','111B','Active','Relief Aire APM System with LAL - 42" x 80"','Mattress/Bed',
     date '2026-06-10', 14, 420, null, 'Confirm purchase price'),
  ('Eden','Vance, Paula','210A','Active','Signa Relief APM System with LAL','Mattress/Bed',
     date '2026-02-03', 6, 180, 666, ''),
  ('Eden','Kenneth Misejka','107B','Active','Wound Vac (WHT)','Wound Care',
     date '2026-05-22', null, null, null, 'Confirm rate / purchase price')
) as x(fac, resident, room, status, equipment, category,
       start_date, daily, monthly, purchase, comments)
  on x.fac = f.name;

commit;

-- Quick check — should mirror the workbook's Portfolio Summary:
--   Champion City : 7 items, $810/mo, 3 to review
--   Eden          : 6 items, $1,155/mo, 2 to review
-- select name, items, monthly_total, to_review from v_portfolio_summary;
