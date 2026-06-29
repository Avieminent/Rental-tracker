// ============================================================
// ECG Operations Platform — API
// Express + Postgres. JWT auth, per-facility scoping on every request,
// a generic record store backing all modules, and write audit logging.
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
const APP_URL = process.env.APP_URL || "http://localhost:5173";
const MAIL = {
  tenant: process.env.GRAPH_TENANT_ID, clientId: process.env.GRAPH_CLIENT_ID,
  clientSecret: process.env.GRAPH_CLIENT_SECRET, from: process.env.MAIL_FROM,
};
const mailConfigured = !!(MAIL.tenant && MAIL.clientId && MAIL.clientSecret && MAIL.from);

const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "2mb" }));

const httpError = (status, msg) => { const e = new Error(msg); e.status = status; return e; };
const wrap = (fn) => (req, res) => fn(req, res).catch((e) =>
  res.status(e.status || 500).json({ error: e.status ? e.message : "Server error." }));

function authenticate(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Not signed in." });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    req.user = { id: p.sub, email: p.email, role: p.role, facilityId: p.facilityId || null };
    next();
  } catch { return res.status(401).json({ error: "Session expired." }); }
}
const seesAll = (u) => u.role === "admin" || u.role === "corporate";
const assertFacility = (user, facilityId) => {
  if (seesAll(user)) return;
  if (user.facilityId !== facilityId) throw httpError(403, "Not allowed for your facility.");
};
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admins only." });
  next();
}
const log = (user, action, module, facilityId, recordId) =>
  pool.query("insert into access_log (user_email, action, module, facility_id, record_id) values ($1,$2,$3,$4,$5)",
    [user?.email || null, action, module || null, facilityId || null, recordId || null]).catch(() => {});

// Rate-limiting (in-memory, per IP).
function makeLimiter(max, windowMs, message) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now(), key = req.ip || "x";
    let e = hits.get(key);
    if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + windowMs }; hits.set(key, e); }
    if (++e.count > max) {
      const mins = Math.ceil((e.resetAt - now) / 60000);
      return res.status(429).json({ error: `${message} Try again in about ${mins} minute(s).` });
    }
    next();
  };
}
const rateLimitLogin = makeLimiter(10, 15 * 60 * 1000, "Too many sign-in attempts.");
const rateLimitReset = makeLimiter(5, 15 * 60 * 1000, "Too many password-reset requests.");

// Email via Microsoft 365 (Graph). No-op (with a warning) until configured.
async function sendMail(to, subject, html) {
  if (!mailConfigured) { console.warn("Email not configured; skipping send to", to); return false; }
  const tr = await fetch(`https://login.microsoftonline.com/${MAIL.tenant}/oauth2/v2.0/token`, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: MAIL.clientId, client_secret: MAIL.clientSecret, scope: "https://graph.microsoft.com/.default", grant_type: "client_credentials" }),
  });
  if (!tr.ok) throw new Error("Graph token failed");
  const { access_token } = await tr.json();
  const sr = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(MAIL.from)}/sendMail`, {
    method: "POST", headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ message: { subject, body: { contentType: "HTML", content: html }, toRecipients: [{ emailAddress: { address: to } }] }, saveToSentItems: false }),
  });
  if (!sr.ok) throw new Error("Graph sendMail failed");
  return true;
}

/* ---------- auth ---------- */
app.post("/api/login", rateLimitLogin, wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query("select * from app_user where lower(email)=lower($1)", [email || ""]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password || "", u.password_hash))) {
    log({ email: (email || "").trim() }, "login_failed", null, null, null);
    throw httpError(401, "Invalid credentials.");
  }
  const token = jwt.sign({ sub: u.id, email: u.email, role: u.role, facilityId: u.facility_id }, JWT_SECRET, { expiresIn: "12h" });
  log(u, "login", null, u.facility_id, null);
  res.json({ token, user: { id: u.id, email: u.email, role: u.role, facilityId: u.facility_id } });
}));

/* ---------- forgot / reset password ---------- */
app.post("/api/forgot", rateLimitReset, async (req, res) => {
  const { email } = req.body || {};
  try {
    const { rows } = await pool.query("select id, email from app_user where lower(email)=lower($1)", [email || ""]);
    const u = rows[0];
    if (u) {
      const token = crypto.randomBytes(32).toString("hex");
      const hash = crypto.createHash("sha256").update(token).digest("hex");
      await pool.query("insert into password_reset (token_hash, user_id, expires_at) values ($1,$2,$3)",
        [hash, u.id, new Date(Date.now() + 3600e3)]);
      await sendMail(u.email, "Reset your ECG platform password",
        `<p>We received a request to reset your password.</p><p><a href="${APP_URL}/?reset=${token}">Choose a new password</a> — expires in 1 hour, single use.</p><p>If you didn't request this, ignore this email.</p>`);
      log(u, "password_reset_sent", null, null, null);
    }
  } catch (e) { console.error("forgot:", e.message); }
  res.json({ ok: true });
});

app.post("/api/reset", rateLimitReset, wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const hash = crypto.createHash("sha256").update(String(token || "")).digest("hex");
  const { rows } = await pool.query("select * from password_reset where token_hash=$1", [hash]);
  const pr = rows[0];
  if (!pr || pr.used_at || new Date(pr.expires_at) < new Date()) throw httpError(400, "This reset link is invalid or expired.");
  await pool.query("update app_user set password_hash=$2 where id=$1", [pr.user_id, await bcrypt.hash(String(password), 10)]);
  await pool.query("update password_reset set used_at=now() where token_hash=$1", [hash]);
  const { rows: u } = await pool.query("select email from app_user where id=$1", [pr.user_id]);
  log({ email: u[0]?.email }, "password_reset", null, null, null);
  res.json({ ok: true });
}));

app.get("/api/me", authenticate, (req, res) => res.json({ user: req.user }));

/* ---------- bootstrap: facilities + records the user may see ---------- */
app.get("/api/bootstrap", authenticate, wrap(async (req, res) => {
  const corp = seesAll(req.user);
  const facilities = (await (corp
    ? pool.query("select * from facility order by sort_order, name")
    : pool.query("select * from facility where id=$1", [req.user.facilityId]))).rows;
  const records = (await (corp
    ? pool.query("select id, facility_id, module, collection, data from record")
    : pool.query("select id, facility_id, module, collection, data from record where facility_id=$1", [req.user.facilityId]))).rows;
  log(req.user, "bootstrap", null, req.user.facilityId, null);
  res.json({
    user: { email: req.user.email, role: req.user.role, facilityId: req.user.facilityId },
    facilities, records,
  });
}));

/* ---------- generic record CRUD (all modules) ---------- */
app.post("/api/records", authenticate, wrap(async (req, res) => {
  const { module, collection, facilityId, data } = req.body || {};
  if (!module || !collection || !facilityId) throw httpError(400, "module, collection, facilityId required.");
  assertFacility(req.user, facilityId);
  const { rows } = await pool.query(
    "insert into record (facility_id, module, collection, data) values ($1,$2,$3,$4) returning id",
    [facilityId, module, collection, data || {}]);
  log(req.user, "create", module, facilityId, rows[0].id);
  res.status(201).json({ id: rows[0].id });
}));

app.patch("/api/records/:id", authenticate, wrap(async (req, res) => {
  const { rows: found } = await pool.query("select facility_id, module from record where id=$1", [req.params.id]);
  if (!found[0]) throw httpError(404, "Record not found.");
  assertFacility(req.user, found[0].facility_id);
  await pool.query("update record set data=$2 where id=$1", [req.params.id, req.body?.data || {}]);
  log(req.user, "update", found[0].module, found[0].facility_id, req.params.id);
  res.json({ ok: true });
}));

app.delete("/api/records/:id", authenticate, wrap(async (req, res) => {
  const { rows: found } = await pool.query("select facility_id, module from record where id=$1", [req.params.id]);
  if (!found[0]) return res.status(204).end();
  assertFacility(req.user, found[0].facility_id);
  await pool.query("delete from record where id=$1", [req.params.id]);
  log(req.user, "delete", found[0].module, found[0].facility_id, req.params.id);
  res.status(204).end();
}));

/* ---------- facility metadata (corporate can edit the roster profile) ---------- */
app.patch("/api/facilities/:id", authenticate, wrap(async (req, res) => {
  assertFacility(req.user, req.params.id);
  const allowed = ["tagline", "location", "beds", "rdo", "rdcs", "nha", "don", "survey", "rating_overall", "rating_staffing", "total_staff", "open_roles"];
  const sets = [], vals = [req.params.id];
  Object.entries(req.body || {}).forEach(([k, v]) => { if (allowed.includes(k)) { vals.push(v); sets.push(`${k}=$${vals.length}`); } });
  if (!sets.length) return res.json({ ok: true });
  await pool.query(`update facility set ${sets.join(", ")} where id=$1`, vals);
  res.json({ ok: true });
}));

/* ---------- login manager (admin only) ---------- */
const ROLES = ["admin", "corporate", "facility"];
const toUser = (r) => ({ id: r.id, email: r.email, role: r.role, facilityId: r.facility_id, facilityName: r.facility_name || null });
const roleScope = (role, fid) => {
  if (!ROLES.includes(role)) throw httpError(400, "Unknown role.");
  if (role === "facility") { if (!fid) throw httpError(400, "Pick a facility for a facility login."); return fid; }
  return null;
};

app.get("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select u.id,u.email,u.role,u.facility_id,f.name facility_name from app_user u left join facility f on f.id=u.facility_id
     order by case u.role when 'admin' then 0 when 'corporate' then 1 else 2 end, u.email`);
  res.json(rows.map(toUser));
}));

app.post("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { email, role, facilityId, password } = req.body || {};
  if (!email || !String(email).trim()) throw httpError(400, "Email is required.");
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const fid = roleScope(role, facilityId);
  let rows;
  try {
    ({ rows } = await pool.query("insert into app_user (email,role,facility_id,password_hash) values (lower($1),$2,$3,$4) returning *",
      [String(email).trim(), role, fid, await bcrypt.hash(String(password), 10)]));
  } catch (e) { if (e.code === "23505") throw httpError(409, "That email already exists."); throw e; }
  const { rows: f } = await pool.query("select name from facility where id=$1", [fid]);
  log(req.user, "user_create", null, fid, null);
  res.status(201).json(toUser({ ...rows[0], facility_name: f[0]?.name }));
}));

app.patch("/api/users/:id/password", authenticate, requireAdmin, wrap(async (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 8) throw httpError(400, "Password must be at least 8 characters.");
  const { rows } = await pool.query("update app_user set password_hash=$2 where id=$1 returning email", [req.params.id, await bcrypt.hash(String(password), 10)]);
  if (!rows[0]) throw httpError(404, "Login not found.");
  log(req.user, "user_reset_password", null, null, null);
  res.json({ ok: true });
}));

app.delete("/api/users/:id", authenticate, requireAdmin, wrap(async (req, res) => {
  if (req.params.id === req.user.id) throw httpError(400, "You can't delete your own login.");
  const { rows } = await pool.query("select role from app_user where id=$1", [req.params.id]);
  if (!rows[0]) throw httpError(404, "Login not found.");
  if (rows[0].role === "admin") {
    const { rows: c } = await pool.query("select count(*)::int n from app_user where role='admin'");
    if (c[0].n <= 1) throw httpError(400, "Can't remove the last admin login.");
  }
  await pool.query("delete from app_user where id=$1", [req.params.id]);
  log(req.user, "user_delete", null, null, null);
  res.status(204).end();
}));

/* ---------- activity log (admin only, read-only, hidden in UI) ---------- */
app.get("/api/audit", authenticate, requireAdmin, wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
  const { rows } = await pool.query(
    `select a.id,a.at,a.user_email,a.action,a.module,a.facility_id,f.name facility_name
     from access_log a left join facility f on f.id=a.facility_id order by a.at desc limit $1`, [limit]);
  res.json(rows.map((r) => ({ id: String(r.id), at: r.at, email: r.user_email, action: r.action, module: r.module, facilityName: r.facility_name || null })));
}));

app.listen(PORT, () => console.log(`ECG Platform API on :${PORT}`));
