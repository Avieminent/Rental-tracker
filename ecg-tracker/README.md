# Eminent Care Group — Equipment Rental Tracker

Tracks rental medical equipment across the ECG facilities (the gear that isn't
in PCC), with automatic rent-vs-buy recommendations and a corporate portfolio
roll-up — behind real logins.

## Three login levels

- **Administrator** — sees/edits every facility, the portfolio dashboard, *and*
  a **Logins** screen to add, reset, and remove logins.
- **Corporate** — sees/edits every facility and the dashboard, but no Logins screen.
- **Facility** — sees/edits only its own building. Never sees other facilities,
  and the Portfolio tab is hidden.

The separation is enforced by the API on every request, so it can't be bypassed
in the browser. The first administrator login is created once by `seed-users.js`;
after that the administrator manages everyone else from inside the app.

## What's in this folder

```
ecg-tracker/
├─ web/                 the website (front end)
│  ├─ index.html        ← the one line you edit: window.__ECG_API_URL__
│  ├─ package.json
│  ├─ vite.config.js
│  └─ src/
│     ├─ App.jsx        the whole app UI
│     └─ main.jsx
├─ api/                 the server + database (back end)
│  ├─ server.js         the API; enforces who-sees-what on every request
│  ├─ schema.sql        tables + calc views + app_user + audit_log + password_reset
│  ├─ seed.sql          the 8 facilities + Champion City / Eden data
│  ├─ seed-users.js     creates the first logins and prints their passwords
│  ├─ package.json
│  └─ .env.example
└─ .gitignore
```

`web/` and `api/` are two separate programs. The website talks to the API over
the network; the API talks to the database.

## Setup (run once)

You need three things running: a **Postgres database**, the **API**, and the
**web** front end. You'll need Node.js installed (nodejs.org) and a Postgres
database (a free one at neon.tech works, or local Postgres).

### 1 — Load the database

```bash
cd api
psql "<your-database-url>" -f schema.sql
psql "<your-database-url>" -f seed.sql
# sanity check — expect: Champion City 7 / 810 / 3 ; Eden 6 / 1155 / 2
psql "<your-database-url>" -c "select name, items, monthly_total, to_review from v_portfolio_summary;"
```

(On Neon, you can instead paste the contents of `schema.sql` then `seed.sql`
into its SQL Editor and run them.)

### 2 — Start the API

```bash
cd api
cp .env.example .env       # set DATABASE_URL and a long random JWT_SECRET
npm install
npm run seed:users         # prints every login + a temporary password — SAVE THESE
npm start                  # API now running on http://localhost:4000
```

`seed:users` creates `ops@eminentcare.com` (administrator),
`corporate@eminentcare.com` (corporate), and one login per facility like
`championcity@eminentcare.com`. Share each facility login only with that
facility, and change passwords after first sign-in. From then on the
administrator adds/resets/removes logins from the in-app **Logins** tab.

### 3 — Start the website

```bash
cd web
npm install
npm run dev                # opens the app — sign in with a login from step 2
```

The website finds the API via one line in `web/index.html`:
```html
<script>window.__ECG_API_URL__ = "http://localhost:4000"</script>
```
Change that to your deployed API's address when you go live (and set the API's
`CORS_ORIGIN` to your website's address).

## Password-reset email (Microsoft 365) — optional

Self-service "Forgot password?" emails a reset link. It's off until these four
values are set in `api/.env`; leave them blank and the feature simply hides the
work behind admin resets.

It sends through your Microsoft 365 — no new email service, no extra license.
A Microsoft 365 **admin** does this one-time setup:

1. In the Microsoft **Entra admin center** → **App registrations** → **New
   registration**. Name it e.g. "ECG Rental Tracker". This is not a user account.
2. Copy the **Directory (tenant) ID** and **Application (client) ID**.
3. Under **Certificates & secrets** → **New client secret**, copy the secret
   **value** (shown once).
4. Under **API permissions** → **Add a permission** → **Microsoft Graph** →
   **Application permissions** → **Mail.Send**, then **Grant admin consent**.
5. Pick a "from" address — a free **shared mailbox** like `noreply@yourdomain`
   is ideal (no license needed). (Best practice: scope the app so it can only
   send from that one mailbox, via Exchange "application access policy".)
6. Put the values in `api/.env`:
   ```
   GRAPH_TENANT_ID=...        GRAPH_CLIENT_ID=...
   GRAPH_CLIENT_SECRET=...    MAIL_FROM=noreply@yourdomain
   APP_URL=https://your-website-url   # so the emailed link points back here
   ```

Maintenance is minimal: the client secret expires (you choose 6–24 months at
step 3), and when it does, reset emails stop until an admin makes a new secret
and updates `GRAPH_CLIENT_SECRET`. Set a calendar reminder.

## Going live (hosting)

For real use you'd host all three pieces: the database (e.g. Neon), the API
(e.g. Render), and the website (e.g. Vercel). The free tiers are fine to test,
but the API's free tier sleeps when idle, so budget a modest paid tier (~$15–25/mo
total) for a tool people rely on.

## The recommendation logic (in api/schema.sql)

```
monthly_effective = monthly_rate, or daily_rate * 30
days_out          = today - start_date         (0 if no start date)
rental_to_date    = monthly_effective * days_out / 30
break_even_months = purchase_price / monthly_effective

rental_to_date >= purchase_price  -> buy       (past break-even)
break_even_months <= 3            -> consider  (pays for itself fast)
otherwise                         -> rent
(missing rate or price            -> none)
```
`to_review` on the dashboard counts items that are `buy` or `consider`.

## API routes (all enforce access)

| Method | Route | Who |
|--------|-------|-----|
| `POST` | `/api/login` | anyone (rate-limited) |
| `POST` | `/api/forgot`, `/api/reset` | anyone (rate-limited) — self-service password reset |
| `GET`  | `/api/bootstrap` | scoped to caller |
| `POST` | `/api/facilities/:fid/items` | admin/corporate or that facility |
| `PATCH`| `/api/items/:id` | admin/corporate or owning facility |
| `DELETE`| `/api/items/:id` | admin/corporate or owning facility |
| `PATCH`| `/api/facilities/:fid` | admin/corporate or that facility |
| `GET`  | `/api/portfolio` | admin or corporate |
| `GET`/`POST`/`PATCH`/`DELETE` | `/api/users*` | admin only (login manager) |
| `GET`  | `/api/audit` | admin only (activity log) |

## Honest notes

- The front end was verified to compile and the API to boot; the one thing not
  run here is a live Postgres, so the database step is your first real test.
- **Security built in:** access is enforced server-side on every request;
  passwords are bcrypt-hashed; queries are parameterized. Sign-in is
  rate-limited (10 tries per IP per 15 min) to blunt password guessing, and an
  append-only **audit log** records sign-ins and every create/edit/delete — the
  admin reads it on the **Activity** tab.
- **Turn on when hosting:** HTTPS is automatic on Render/Vercel (required — it
  protects passwords in transit); keep a long random `JWT_SECRET`. For HIPAA,
  sign a BAA with each host (Neon/Render/Vercel offer these on paid tiers).
- **Multi-factor auth** is deliberately not included.
- **Self-service password reset** is built in but **off until you configure email**
  (see below). With it off, admins still reset passwords on the Logins tab.
- The audit log lives in the same database as the data. That's right-sized for
  an internal tool; a stricter setup would ship logs to a separate write-only
  store so even a database admin couldn't alter them.
- **Atrium** has no logo in the source files, so its page uses the crown + name
  fallback until you add one.
- Keep PHI handling aligned with your existing PCC/HIPAA policies.
```
