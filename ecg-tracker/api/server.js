// ============================================================
// Eminent Care Group — Rental Tracker API
// Express + Postgres. Enforces per-facility access on every route:
//   - corporate users see/modify all facilities
//   - facility users are pinned to their own facility_id
// ============================================================
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pg from "pg";
import crypto from "node:crypto";
import "dotenv/config";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const PORT = process.env.PORT || 4000;

// Where the web app lives (used to build reset links emailed to users).
const APP_URL = process.env.APP_URL || "http://localhost:5173";
// Microsoft 365 (Graph) email config for password-reset emails. If any are
// blank, the app still runs — it just skips sending and logs a warning.
const MAIL = {
  tenant: process.env.GRAPH_TENANT_ID,
  clientId: process.env.GRAPH_CLIENT_ID,
  clientSecret: process.env.GRAPH_CLIENT_SECRET,
  from: process.env.MAIL_FROM,
};
const mailConfigured = !!(MAIL.tenant && MAIL.clientId && MAIL.clientSecret && MAIL.from);

const CATEGORIES = ["Mattress/Bed", "Oxygen/Respiratory", "Wound Care", "Mobility", "Other"];
const STATUSES = ["Active", "Pending Order", "Discontinued"];

const app = express();
app.set("trust proxy", 1); // we run behind a host proxy (Render/Vercel); use the real client IP
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json());

/* ---------- helpers ---------- */
// DB row -> the shape the front end expects (camelCase rates).
const toItem = (r) => ({
  id: r.id,
  resident: r.resident || "",
  room: r.room || "",
  status: r.status,
  equipment: r.equipment,
  category: r.category,
  vendor: r.vendor || "",
  startDate: r.start_date ? new Date(r.start_date).toISOString().slice(0, 10) : "",
  daily: r.daily_rate != null ? Number(r.daily_rate) : null,
  monthly: r.monthly_rate != null ? Number(r.monthly_rate) : null,
  purchase: r.purchase_price != null ? Number(r.purchase_price) : null,
  comments: r.comments || "",
});

// Validate + normalize an incoming item payload into DB columns.
function toCols(body) {
  if (!body.equipment || !String(body.equipment).trim()) throw httpError(400, "Equipment is required.");
  const category = CATEGORIES.includes(body.category) ? body.category : "Mattress/Bed";
  const status = STATUSES.includes(body.status) ? body.status : "Active";
  const n = (v) => (v === "" || v == null || isNaN(+v) ? null : +v);
  return {
    resident: body.resident || null,
    room: body.room || null,
    status,
    equipment: String(body.equipment).trim(),
    category,
    vendor: body.vendor || null,
    start_date: body.startDate || null,
    daily_rate: n(body.daily),
    monthly_rate: n(body.monthly),
    purchase_price: n(body.purchase),
    comments: body.comments || null,
  };
}

function httpError(status, msg) { const e = new Error(msg); e.status = status; return e; }

// ---- Rate-limiting (in-memory, per client IP) ----
// Note: per-instance and resets on restart — fine for a single small deployment.
function makeLimiter(max, windowMs, message) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || "unknown";
    let e = hits.get(key);
    if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + windowMs }; hits.set(key, e); }
    e.count++;
    if (e.count > max) {
      const mins = Math.ceil((e.resetAt - now) / 60000);
      return res.status(429).json({ error: `${message} Try again in about ${mins} minute(s).` });
    }
    next();
  };
}
const rateLimitLogin = makeLimiter(10, 15 * 60 * 1000, "Too many sign-in attempts.");
const rateLimitReset = makeLimiter(5, 15 * 60 * 1000, "Too many password-reset requests.");

// ---- Email via Microsoft 365 (Graph, client-credentials) ----
async function sendMail(to, subject, html) {
  if (!mailConfigured) { console.warn("Email not configured (GRAPH_* / MAIL_FROM); skipping send to", to); return false; }
  const tokenRes = await fetch(`https://login.microsoftonline.com/${MAIL.tenant}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: MAIL.clientId, client_secret: MAIL.clientSecret,
      scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials",
    }),
  });
  if (!tokenRes.ok) throw new Error("Graph token request failed: " + (await tokenRes.text()));
  const { access_token } = await tokenRes.json();
  const sendRes = await fetch(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(MAIL.from)}/sendMail`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        message: { subject, body: { contentType: "HTML", content: html }, toRecipients: [{ emailAddress: { address: to } }] },
        saveToSentItems: false,
      }),
    }
  );
  if (!sendRes.ok) throw new Error("Graph sendMail failed: " + (await sendRes.text()));
  return true;
}

// ---- Audit log (append-only) ----
// Logging must never break a request, so failures here are swallowed (logged to console).
async function writeAudit({ userId = null, email = null, role = null, action, facilityId = null, detail = null }) {
  try {
    await pool.query(
      `insert into audit_log (user_id, user_email, role, action, facility_id, detail)
       values ($1,$2,$3,$4,$5,$6)`,
      [userId, email, role, action, facilityId, detail]
    );
  } catch (e) { console.error("audit write failed:", e.message); }
}
const auditReq = (req, action, opts = {}) =>
  writeAudit({ userId: req.user?.id, email: req.user?.email, role: req.user?.role, action, ...opts });

// auth middleware -> req.user = { id, role, facilityId }
function authenticate(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Not signed in." });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    req.user = { id: p.sub, role: p.role, facilityId: p.facilityId || null, email: p.email || null };
    next();
  } catch {
    return res.status(401).json({ error: "Session expired." });
  }
}

// Admin and corporate both span every facility; facility users are pinned.
function seesAll(user) { return user.role === "admin" || user.role === "corporate"; }

// Throws 403 unless the user may touch this facility.
function assertFacility(user, facilityId) {
  if (seesAll(user)) return;
  if (user.facilityId !== facilityId) throw httpError(403, "Not allowed for your facility.");
}

// Throws 403 unless the user is an admin (login manager).
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admins only." });
  next();
}

// Look up the facility that owns an item (and authorize).
async function facilityOfItem(itemId) {
  const { rows } = await pool.query("select facility_id from rental_item where id = $1", [itemId]);
  if (!rows[0]) throw httpError(404, "Item not found.");
  return rows[0].facility_id;
}

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  res.status(e.status || 500).json({ error: e.status ? e.message : "Server error." });
});

/* ---------- auth ---------- */
app.post("/api/login", rateLimitLogin, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query("select * from app_user where lower(email) = lower($1)", [email || ""]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password || "", u.password_hash))) {
    await writeAudit({ email: (email || "").trim() || null, action: "login_failed", detail: "invalid credentials" });
    throw httpError(401, "Invalid credentials.");
  }
  await writeAudit({ userId: u.id, email: u.email, role: u.role, action: "login" });
  const token = jwt.sign({ sub: u.id, role: u.role, facilityId: u.facility_id, email: u.email }, JWT_SECRET, { expiresIn: "12h" });
  res.json({ token, user: { id: u.id, email: u.email, role: u.role, facilityId: u.facility_id } });
}));

app.get("/api/me", authenticate, (req, res) => res.json({ user: req.user }));

/* ---------- forgot / reset password ---------- */
// Always responds the same way, so it never reveals which emails exist.
app.post("/api/forgot", rateLimitReset, async (req, res) => {
  const { email } = req.body || {};
  try {
    const { rows } = await pool.query("select id, email from app_user where lower(email) = lower($1)", [email || ""]);
    const u = rows[0];
    if (u) {
      const token = crypto.randomBytes(32).toString("hex");
      const hash = crypto.createHash("sha256").update(token).digest("hex");
      const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await pool.query(
        "insert into password_reset (token_hash, user_id, expires_at) values ($1,$2,$3)",
        [hash, u.id, expires]
      );
      const link = `${APP_URL}/?reset=${token}`;
      await sendMail(
        u.email,
        "Reset your ECG Rental Tracker password",
        `<p>We received a request to reset the password for this account.</p>
         <p><a href="${link}">Choose a new password</a> — this link expires in 1 hour and can be used once.</p>
         <p>If you didn't request this, you can safely ignore this email; your password won't change.</p>`
      );
      await writeAudit({ userId: u.id, email: u.email, action: "password.forgot_sent" });
    } else {
      await writeAudit({ email: (email || "").trim() || null, action: "password.forgot_unknown" });
    }
  } catch (e) {
    console.error("forgot:", e.message);
  }
  res.json({ ok: true }); // identical response regardless of outcome
});

app.post("/api/reset", rateLimitReset, wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const hash = crypto.createHash("sha256").update(String(token || "")).digest("hex");
  const { rows } = await pool.query("select * from password_reset where token_hash = $1", [hash]);
  const pr = rows[0];
  if (!pr || pr.used_at || new Date(pr.expires_at) < new Date())
    throw httpError(400, "This reset link is invalid or has expired. Request a new one.");
  const pwHash = await bcrypt.hash(String(password), 10);
  await pool.query("update app_user set password_hash = $2 where id = $1", [pr.user_id, pwHash]);
  await pool.query("update password_reset set used_at = now() where token_hash = $1", [hash]);
  const { rows: u } = await pool.query("select email from app_user where id = $1", [pr.user_id]);
  await writeAudit({ userId: pr.user_id, email: u[0]?.email, action: "password.reset" });
  res.json({ ok: true });
}));

/* ---------- bootstrap: everything the user is allowed to see ---------- */
app.get("/api/bootstrap", authenticate, wrap(async (req, res) => {
  const facQuery = seesAll(req.user)
    ? pool.query("select * from facility order by sort_order, name")
    : pool.query("select * from facility where id = $1", [req.user.facilityId]);
  const facilities = (await facQuery).rows;
  const ids = facilities.map((f) => f.id);
  const items = ids.length
    ? (await pool.query("select * from rental_item where facility_id = any($1) order by created_at", [ids])).rows
    : [];
  const byFac = {};
  items.forEach((r) => { (byFac[r.facility_id] ||= []).push(toItem(r)); });
  res.json({
    user: { role: req.user.role, facilityId: req.user.facilityId },
    facilities: facilities.map((f) => ({
      id: f.id, name: f.name, tagline: f.tagline, location: f.location || "",
      items: byFac[f.id] || [],
    })),
  });
}));

/* ---------- items ---------- */
app.post("/api/facilities/:fid/items", authenticate, wrap(async (req, res) => {
  assertFacility(req.user, req.params.fid);
  const c = toCols(req.body);
  const { rows } = await pool.query(
    `insert into rental_item
       (facility_id, resident, room, status, equipment, category, vendor, start_date, daily_rate, monthly_rate, purchase_price, comments)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) returning *`,
    [req.params.fid, c.resident, c.room, c.status, c.equipment, c.category, c.vendor, c.start_date, c.daily_rate, c.monthly_rate, c.purchase_price, c.comments]
  );
  res.status(201).json(toItem(rows[0]));
  auditReq(req, "item.create", { facilityId: req.params.fid, detail: `${c.equipment} · ${c.resident || "—"}` });
}));

app.patch("/api/items/:id", authenticate, wrap(async (req, res) => {
  const fid = await facilityOfItem(req.params.id);
  assertFacility(req.user, fid);
  const c = toCols(req.body);
  const { rows } = await pool.query(
    `update rental_item set
       resident=$2, room=$3, status=$4, equipment=$5, category=$6, vendor=$7,
       start_date=$8, daily_rate=$9, monthly_rate=$10, purchase_price=$11, comments=$12
     where id=$1 returning *`,
    [req.params.id, c.resident, c.room, c.status, c.equipment, c.category, c.vendor, c.start_date, c.daily_rate, c.monthly_rate, c.purchase_price, c.comments]
  );
  res.json(toItem(rows[0]));
  auditReq(req, "item.update", { facilityId: fid, detail: `${c.equipment} · ${c.resident || "—"}` });
}));

app.delete("/api/items/:id", authenticate, wrap(async (req, res) => {
  const fid = await facilityOfItem(req.params.id);
  assertFacility(req.user, fid);
  await pool.query("delete from rental_item where id = $1", [req.params.id]);
  res.status(204).end();
  auditReq(req, "item.delete", { facilityId: fid, detail: req.params.id });
}));

/* ---------- facility metadata ---------- */
app.patch("/api/facilities/:fid", authenticate, wrap(async (req, res) => {
  assertFacility(req.user, req.params.fid);
  const { name, tagline, location } = req.body || {};
  const { rows } = await pool.query(
    `update facility set
       name = coalesce($2, name),
       tagline = coalesce($3, tagline),
       location = $4
     where id = $1 returning id, name, tagline, location`,
    [req.params.fid, name || null, tagline || null, location ?? null]
  );
  if (!rows[0]) throw httpError(404, "Facility not found.");
  res.json({ name: rows[0].name, tagline: rows[0].tagline, location: rows[0].location || "" });
  auditReq(req, "facility.update", { facilityId: req.params.fid, detail: rows[0].name });
}));

/* ---------- optional: portfolio straight from the DB view (corporate) ---------- */
app.get("/api/portfolio", authenticate, wrap(async (req, res) => {
  if (!seesAll(req.user)) throw httpError(403, "Corporate only.");
  const { rows } = await pool.query("select * from v_portfolio_summary");
  res.json(rows);
}));

/* ---------- login management (admin only) ---------- */
const ROLES = ["admin", "corporate", "facility"];

// Shape a user row for the front end (never expose password_hash).
const toUser = (r) => ({
  id: r.id, email: r.email, role: r.role,
  facilityId: r.facility_id, facilityName: r.facility_name || null,
});

// Validate + normalize a role/facility pairing.
function roleScope(role, facilityId) {
  if (!ROLES.includes(role)) throw httpError(400, "Unknown role.");
  if (role === "facility") {
    if (!facilityId) throw httpError(400, "Pick a facility for a facility login.");
    return facilityId;
  }
  return null; // admin / corporate span all facilities
}

app.get("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select u.id, u.email, u.role, u.facility_id, f.name as facility_name
       from app_user u left join facility f on f.id = u.facility_id
      order by case u.role when 'admin' then 0 when 'corporate' then 1 else 2 end, u.email`
  );
  res.json(rows.map(toUser));
}));

app.post("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { email, role, facilityId, password } = req.body || {};
  if (!email || !String(email).trim()) throw httpError(400, "Email is required.");
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const fid = roleScope(role, facilityId);
  const hash = await bcrypt.hash(String(password), 10);
  let rows;
  try {
    ({ rows } = await pool.query(
      `insert into app_user (email, role, facility_id, password_hash)
       values (lower($1),$2,$3,$4) returning *`,
      [String(email).trim(), role, fid, hash]
    ));
  } catch (e) {
    if (e.code === "23505") throw httpError(409, "A login with that email already exists.");
    throw e;
  }
  const { rows: f } = await pool.query("select name from facility where id = $1", [fid]);
  res.status(201).json(toUser({ ...rows[0], facility_name: f[0]?.name }));
  auditReq(req, "user.create", { facilityId: fid, detail: `${rows[0].email} (${rows[0].role})` });
}));

app.patch("/api/users/:id/password", authenticate, requireAdmin, wrap(async (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const hash = await bcrypt.hash(String(password), 10);
  const { rows } = await pool.query("update app_user set password_hash = $2 where id = $1 returning email", [req.params.id, hash]);
  if (!rows[0]) throw httpError(404, "Login not found.");
  res.json({ ok: true });
  auditReq(req, "user.reset_password", { detail: rows[0].email });
}));

app.delete("/api/users/:id", authenticate, requireAdmin, wrap(async (req, res) => {
  if (req.params.id === req.user.id) throw httpError(400, "You can't delete your own login.");
  const { rows } = await pool.query("select role, email from app_user where id = $1", [req.params.id]);
  if (!rows[0]) throw httpError(404, "Login not found.");
  if (rows[0].role === "admin") {
    const { rows: c } = await pool.query("select count(*)::int as n from app_user where role = 'admin'");
    if (c[0].n <= 1) throw httpError(400, "Can't remove the last admin login.");
  }
  await pool.query("delete from app_user where id = $1", [req.params.id]);
  res.status(204).end();
  auditReq(req, "user.delete", { detail: rows[0].email });
}));

/* ---------- audit log (admin only, read-only) ---------- */
app.get("/api/audit", authenticate, requireAdmin, wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
  const { rows } = await pool.query(
    `select a.id, a.at, a.user_email, a.role, a.action, a.detail, a.facility_id, f.name as facility_name
       from audit_log a left join facility f on f.id = a.facility_id
      order by a.at desc limit $1`,
    [limit]
  );
  res.json(rows.map((r) => ({
    id: String(r.id), at: r.at, email: r.user_email, role: r.role,
    action: r.action, detail: r.detail, facilityName: r.facility_name || null,
  })));
}));

app.listen(PORT, () => console.log(`ECG Rental Tracker API on :${PORT}`));
