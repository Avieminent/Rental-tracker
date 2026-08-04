// ============================================================
// Eminent Central — Operations Platform API (v2)
// Express + Postgres. Replaces the old rentals-only server.
//
// What's new vs v1:
//   • Generic record store (/api/bootstrap + /api/records CRUD)
//     powering every module: rentals, roster, staffing, budget,
//     concierge, reviews, rehosp, ar — no schema change per module.
//   • "Remember this device": login accepts { remember } and issues
//     a 30-day token when true, a 12-hour token when false.
//   • Per-facility enforcement on every route (admin/corporate see
//     all; facility logins are pinned to their facility).
//   • Audit trail of logins and every create/update/delete.
//
// Environment (.env): DATABASE_URL, JWT_SECRET, PORT, CORS_ORIGIN,
// APP_URL, and optionally GRAPH_TENANT_ID / GRAPH_CLIENT_ID /
// GRAPH_CLIENT_SECRET / MAIL_FROM for password-reset emails.
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
  tenant: process.env.GRAPH_TENANT_ID,
  clientId: process.env.GRAPH_CLIENT_ID,
  clientSecret: process.env.GRAPH_CLIENT_SECRET,
  from: process.env.MAIL_FROM,
  fromName: process.env.MAIL_FROM_NAME || "Eminent Central",
};
const mailConfigured = !!(MAIL.tenant && MAIL.clientId && MAIL.clientSecret && MAIL.from);
 
const app = express();
app.set("trust proxy", 1);
// Only these web addresses may talk to the API. Add more via CORS_ORIGIN
// (comma-separated) in the .env file if you ever add a domain.
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN
  || "https://eminentcentral.com,https://www.eminentcentral.com")
  .split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    // allow same-origin / server-to-server calls (no Origin header) and the allow-list
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error("Not allowed by CORS"));
  },
}));
app.use(express.json({ limit: "2mb" }));
 
/* ---------- helpers ---------- */
function httpError(status, msg) { const e = new Error(msg); e.status = status; return e; }
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : "Server error." });
});
 
// ---- Rate limiting (in-memory, per client IP) ----
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
async function sendMail(to, subject, html, attachments) {
  if (!mailConfigured) { console.warn("Email not configured; skipping send to", to); return false; }
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
        message: {
          subject,
          body: { contentType: "HTML", content: html },
          from: { emailAddress: { name: MAIL.fromName, address: MAIL.from } },
          toRecipients: [{ emailAddress: { address: to } }],
          ...(Array.isArray(attachments) && attachments.length ? { attachments: attachments.map(a => ({
            "@odata.type": "#microsoft.graph.fileAttachment",
            name: a.name,
            contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            contentBytes: a.contentBase64,
          })) } : {}),
        },
        saveToSentItems: false,
      }),
    }
  );
  if (!sendRes.ok) throw new Error("Graph sendMail failed: " + (await sendRes.text()));
  return true;
}
 
// ---- Audit trail (append-only; must never break a request) ----
async function writeAudit({ userId = null, email = null, role = null, action, facilityId = null, recordId = null, module = null, detail = null }) {
  try {
    await pool.query(
      `insert into audit_log (user_id, user_email, role, action, facility_id, record_id, module, detail)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [userId, email, role, action, facilityId, recordId, module, detail]
    );
  } catch (e) { console.error("audit write failed:", e.message); }
}
const auditReq = (req, action, opts = {}) =>
  writeAudit({ userId: req.user?.id, email: req.user?.email, role: req.user?.role, action, ...opts });
 
// ---- Auth ----
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
function seesAll(user) { return user.role === "admin" || user.role === "corporate"; }
function assertFacility(user, facilityId) {
  if (seesAll(user)) return;
  if (user.facilityId !== facilityId) throw httpError(403, "Not allowed for your facility.");
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admins only." });
  next();
}
 
/* ---------- auth routes ---------- */
app.post("/api/login", rateLimitLogin, wrap(async (req, res) => {
  const { email, password, remember } = req.body || {};
  const { rows } = await pool.query("select * from app_user where lower(email) = lower($1)", [email || ""]);
  const u = rows[0];
  if (u && u.password_hash === "invited") {
    await writeAudit({ userId: u.id, email: u.email, action: "login_failed", detail: "invite not yet accepted" });
    throw httpError(401, "This account hasn't been set up yet — use the invite link in your email (or ask an administrator to resend it).");
  }
  if (!u || !(await bcrypt.compare(password || "", u.password_hash))) {
    await writeAudit({ email: (email || "").trim() || null, action: "login_failed", detail: "invalid credentials" });
    throw httpError(401, "Invalid credentials.");
  }
  // Remember this device -> long-lived token; otherwise a short one.
  const expiresIn = remember ? "30d" : "12h";
  await writeAudit({ userId: u.id, email: u.email, role: u.role, action: "login", detail: remember ? "remembered device (30d)" : "standard session (12h)" });
  const token = jwt.sign({ sub: u.id, role: u.role, facilityId: u.facility_id, email: u.email }, JWT_SECRET, { expiresIn });
  res.json({ token, user: { id: u.id, email: u.email, role: u.role, facilityId: u.facility_id, pages: u.pages || null } });
}));
 
app.get("/api/me", authenticate, (req, res) => res.json({ user: req.user }));
 
/* ---------- invites (invite-only user creation) ---------- */
async function sendInvite(u) {
  const token = crypto.randomBytes(32).toString("hex");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  await pool.query("insert into password_reset (token_hash, user_id, expires_at) values ($1,$2,$3)", [hash, u.id, expires]);
  const link = `${APP_URL}/?reset=${token}`;
  await sendMail(
    u.email,
    "You've been added to Eminent Central",
    `<p>A login has been created for you on <b>Eminent Central</b>, Eminent Care Group's operations platform.</p>
     <p><a href="${link}">Click here to choose your password</a> — this link is valid for 7 days and can be used once.</p>
     <p>After setting your password, sign in at <a href="${APP_URL}">${APP_URL}</a> with this email address.</p>`
  );
  await writeAudit({ userId: u.id, email: u.email, action: "user.invite_sent" });
}
 
/* ---------- forgot / reset password ---------- */
app.post("/api/forgot", rateLimitReset, async (req, res) => {
  const { email } = req.body || {};
  try {
    const { rows } = await pool.query("select id, email from app_user where lower(email) = lower($1)", [email || ""]);
    const u = rows[0];
    if (u) {
      const token = crypto.randomBytes(32).toString("hex");
      const hash = crypto.createHash("sha256").update(token).digest("hex");
      const expires = new Date(Date.now() + 60 * 60 * 1000);
      await pool.query("insert into password_reset (token_hash, user_id, expires_at) values ($1,$2,$3)", [hash, u.id, expires]);
      const link = `${APP_URL}/?reset=${token}`;
      await sendMail(
        u.email,
        "Reset your Eminent Central password",
        `<p>We received a request to reset the password for this account.</p>
         <p><a href="${link}">Choose a new password</a> — this link expires in 1 hour and can be used once.</p>
         <p>If you didn't request this, you can safely ignore this email; your password won't change.</p>`
      );
      await writeAudit({ userId: u.id, email: u.email, action: "password.forgot_sent" });
    } else {
      await writeAudit({ email: (email || "").trim() || null, action: "password.forgot_unknown" });
    }
  } catch (e) { console.error("forgot:", e.message); }
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
 
/* ---------- bootstrap: everything the user may see ---------- */
app.get("/api/bootstrap", authenticate, wrap(async (req, res) => {
  const facQuery = seesAll(req.user)
    ? pool.query("select * from facility order by sort_order, name")
    : pool.query("select * from facility where id = $1", [req.user.facilityId]);
  const facilities = (await facQuery).rows;
  const ids = facilities.map((f) => f.id);
  const records = ids.length
    ? (await pool.query(
        "select id, facility_id, module, collection, data from record where facility_id = any($1) order by created_at",
        [ids]
      )).rows
    : [];
  auditReq(req, "bootstrap");
  res.json({
    user: { role: req.user.role, facilityId: req.user.facilityId },
    facilities, // full rows: name, tagline, location, beds, rdo, rdcs, nha, don, survey, ratings, etc.
    records,    // [{ id, facility_id, module, collection, data }]
  });
}));
 
/* ---------- generic records (every module) ---------- */
// ---- Census "update done" email: per-facility recipient list + send with the bedboard attached ----
const RECIP_MODULE = "census", RECIP_COLLECTION = "email-recipients";
async function getRecipients(facilityId) {
  const { rows } = await pool.query(
    "select id, data from record where facility_id = $1 and module = $2 and collection = $3 limit 1",
    [facilityId, RECIP_MODULE, RECIP_COLLECTION]
  );
  return rows[0] ? { id: rows[0].id, emails: Array.isArray(rows[0].data?.emails) ? rows[0].data.emails : [] } : { id: null, emails: [] };
}
 
app.get("/api/census-recipients/:facilityId", authenticate, wrap(async (req, res) => {
  if (req.user.role !== "admin") throw httpError(403, "Administrators only.");
  res.json({ emails: (await getRecipients(req.params.facilityId)).emails });
}));
 
app.put("/api/census-recipients/:facilityId", authenticate, wrap(async (req, res) => {
  if (req.user.role !== "admin") throw httpError(403, "Administrators only.");
  const emails = (Array.isArray(req.body?.emails) ? req.body.emails : [])
    .map(e => String(e || "").trim().toLowerCase()).filter(e => /.+@.+\..+/.test(e)).slice(0, 50);
  const existing = await getRecipients(req.params.facilityId);
  if (existing.id) await pool.query("update record set data = $2 where id = $1", [existing.id, { emails }]);
  else await pool.query("insert into record (facility_id, module, collection, data) values ($1,$2,$3,$4)",
    [req.params.facilityId, RECIP_MODULE, RECIP_COLLECTION, { emails }]);
  res.json({ ok: true, emails });
  auditReq(req, "update", { facilityId: req.params.facilityId, module: RECIP_MODULE, detail: "email recipients" });
}));
 
app.post("/api/census-done", authenticate, wrap(async (req, res) => {
  const { facilityId, facilityName, dateISO, summary, xlsxBase64 } = req.body || {};
  if (!facilityId || !dateISO) throw httpError(400, "facilityId and dateISO are required.");
  assertFacility(req.user, facilityId);
  // Census page access: admins/corporate, or facility users whose page list includes census.
  if (req.user.role === "facility" && Array.isArray(req.user.pages) && !req.user.pages.includes("census"))
    throw httpError(403, "You don't have access to the census page.");
  const { emails } = await getRecipients(facilityId);
  if (!emails.length) throw httpError(400, "No recipients are set up for this facility yet. An administrator can add them under Census emails.");
  const when = new Date().toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: "America/New_York" });
  const sum = summary || {};
  const html = `
    <p><b>${facilityName || facilityId}</b> — census updated for <b>${dateISO}</b>.</p>
    <p>Marked done by ${req.user.email} at ${when} (ET).</p>
    <table cellpadding="6" style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:13px">
      <tr><td><b>Occupied</b></td><td>${sum.occ ?? "—"}</td><td><b>Available</b></td><td>${sum.avail ?? "—"}</td></tr>
      <tr><td><b>In hospital</b></td><td>${sum.hosp ?? "—"}</td><td><b>Bedhold</b></td><td>${sum.bh ?? "—"}</td></tr>
      <tr><td><b>Admitted today</b></td><td>${sum.admits ?? "—"}</td><td><b>Left today</b></td><td>${sum.left ?? "—"}</td></tr>
    </table>
    <p>The full bed board is attached.</p>`;
  const attachments = xlsxBase64 ? [{ name: `Bedboard_${String(facilityName||facilityId).replace(/\s+/g,"_")}_${dateISO}.xlsx`, contentBase64: xlsxBase64 }] : [];
  let sent = 0;
  for (const to of emails) { try { if (await sendMail(to, `${facilityName || "Facility"} census updated — ${dateISO}`, html, attachments)) sent++; } catch (e) { console.error("census-done mail failed for", to, e.message); } }
  if (!sent) throw httpError(502, "The email could not be sent. Check the mail configuration.");
  res.json({ ok: true, sent, of: emails.length });
  auditReq(req, "update", { facilityId, module: "census", detail: `update-done email to ${sent}/${emails.length}` });
}));
 
app.post("/api/records", authenticate, wrap(async (req, res) => {
  const { module, collection, facilityId, data } = req.body || {};
  if (!module || !collection || !facilityId) throw httpError(400, "module, collection and facilityId are required.");
  assertFacility(req.user, facilityId);
  const { rows } = await pool.query(
    "insert into record (facility_id, module, collection, data) values ($1,$2,$3,$4) returning id",
    [facilityId, module, collection, data || {}]
  );
  res.status(201).json({ id: rows[0].id });
  auditReq(req, "create", { facilityId, recordId: rows[0].id, module, detail: collection });
}));
 
app.get("/api/records/:id", authenticate, wrap(async (req, res) => {
  const { rows } = await pool.query("select id, facility_id, module, collection, data from record where id = $1", [req.params.id]);
  if (!rows[0]) throw httpError(404, "Record not found.");
  assertFacility(req.user, rows[0].facility_id);
  res.json({ id: String(rows[0].id), facilityId: rows[0].facility_id, module: rows[0].module, collection: rows[0].collection, data: rows[0].data });
}));
 
app.patch("/api/records/:id", authenticate, wrap(async (req, res) => {
  const { rows: found } = await pool.query("select facility_id, module, collection from record where id = $1", [req.params.id]);
  if (!found[0]) throw httpError(404, "Record not found.");
  assertFacility(req.user, found[0].facility_id);
  await pool.query("update record set data = $2 where id = $1", [req.params.id, (req.body || {}).data || {}]);
  res.json({ ok: true });
  auditReq(req, "update", { facilityId: found[0].facility_id, recordId: req.params.id, module: found[0].module, detail: found[0].collection });
}));
 
app.delete("/api/records/:id", authenticate, wrap(async (req, res) => {
  const { rows: found } = await pool.query("select facility_id, module, collection from record where id = $1", [req.params.id]);
  if (!found[0]) throw httpError(404, "Record not found.");
  assertFacility(req.user, found[0].facility_id);
  await pool.query("delete from record where id = $1", [req.params.id]);
  res.status(204).end();
  auditReq(req, "delete", { facilityId: found[0].facility_id, recordId: req.params.id, module: found[0].module, detail: found[0].collection });
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
 
/* ---------- login management (admin only) ---------- */
const ROLES = ["admin", "corporate", "facility"];
const PAGE_KEYS = ["roster", "census", "rehosp", "rfms", "staffing", "budget", "rentals", "rfms:sign"]; // rfms:sign = permission to sign RFMS spend-downs
const cleanPages = (v) => Array.isArray(v) ? v.filter((k) => PAGE_KEYS.includes(k)) : null;
const toUser = (r) => ({ id: r.id, email: r.email, role: r.role, facilityId: r.facility_id, facilityName: r.facility_name || null, pages: r.pages || null, invited: r.invited === true });
 
function roleScope(role, facilityId) {
  if (!ROLES.includes(role)) throw httpError(400, "Unknown role.");
  if (role === "facility") {
    if (!facilityId) throw httpError(400, "Pick a facility for a facility login.");
    return facilityId;
  }
  return null;
}
 
app.get("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select u.id, u.email, u.role, u.facility_id, f.name as facility_name, (u.password_hash = 'invited') as invited
       from app_user u left join facility f on f.id = u.facility_id
      order by case u.role when 'admin' then 0 when 'corporate' then 1 else 2 end, u.email`
  );
  res.json(rows.map(toUser));
}));
 
app.post("/api/users", authenticate, requireAdmin, wrap(async (req, res) => {
  const { email, role, facilityId, pages } = req.body || {};
  if (!email || !String(email).trim()) throw httpError(400, "Email is required.");
  const fid = roleScope(role, facilityId);
  const pageList = role === "admin" ? null : cleanPages(pages); // admin: all pages; facility/corporate: their list (may carry rfms:sign)
  const hash = "invited"; // no password until the invite link is used
  let rows;
  try {
    ({ rows } = await pool.query(
      "insert into app_user (email, role, facility_id, password_hash, pages) values (lower($1),$2,$3,$4,$5) returning *",
      [String(email).trim(), role, fid, hash, pageList]
    ));
  } catch (e) {
    if (e.code === "23505") throw httpError(409, "A login with that email already exists.");
    throw e;
  }
  const { rows: f } = await pool.query("select name from facility where id = $1", [fid]);
  let emailFailed = false;
  try { await sendInvite(rows[0]); } catch (e) { emailFailed = true; console.error("invite mail:", e.message); }
  res.status(201).json({ ...toUser({ ...rows[0], facility_name: f[0]?.name }), invited: true, emailFailed });
  auditReq(req, "user.create", { facilityId: fid, detail: `${rows[0].email} (${rows[0].role}) — invite ${emailFailed ? "FAILED to send" : "emailed"}` });
}));
 
// Resend the sign-in link: a fresh invite for pending users, a standard reset for active ones.
app.post("/api/users/:id/invite", authenticate, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query("select * from app_user where id = $1", [req.params.id]);
  const u = rows[0];
  if (!u) throw httpError(404, "No such login.");
  if (u.password_hash === "invited") {
    await sendInvite(u);
  } else {
    const token = crypto.randomBytes(32).toString("hex");
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query("insert into password_reset (token_hash, user_id, expires_at) values ($1,$2,$3)", [hash, u.id, expires]);
    await sendMail(u.email, "Reset your Eminent Central password",
      `<p>An administrator sent you a password reset link for Eminent Central.</p>
       <p><a href="${APP_URL}/?reset=${token}">Choose a new password</a> — this link expires in 1 hour and can be used once.</p>`);
    await writeAudit({ userId: u.id, email: u.email, action: "password.forgot_sent", detail: "sent by admin" });
  }
  res.json({ ok: true, invited: u.password_hash === "invited" });
}));
 
// (removed: manual admin password setting — invite-only; use POST /api/users/:id/invite)
 
 
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
 
app.patch("/api/users/:id/pages", authenticate, requireAdmin, wrap(async (req, res) => {
  const { rows: found } = await pool.query("select role from app_user where id = $1", [req.params.id]);
  if (!found[0]) throw httpError(404, "Login not found.");
  if (found[0].role !== "facility") throw httpError(400, "Page access applies only to facility logins.");
  const pageList = cleanPages((req.body || {}).pages);
  await pool.query("update app_user set pages = $2 where id = $1", [req.params.id, pageList]);
  res.json({ ok: true, pages: pageList });
  auditReq(req, "user.pages", { detail: `${req.params.id}: ${pageList ? pageList.join(",") : "all"}` });
}));
 
/* ---------- audit log (admin only, read-only) ---------- */
app.get("/api/audit", authenticate, requireAdmin, wrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 2000);
  const { from, to, facilityId } = req.query;
  const where = [];
  const params = [];
  if (from) { params.push(from); where.push(`a.at >= $${params.length}`); }
  if (to)   { params.push(to);   where.push(`a.at <= $${params.length}`); }
  if (facilityId) { params.push(facilityId); where.push(`a.facility_id = $${params.length}`); }
  const whereSql = where.length ? "where " + where.join(" and ") : "";
  params.push(limit);
  const { rows } = await pool.query(
    `select a.id, a.at, a.user_email, a.role, a.action, a.module, a.detail, a.facility_id, f.name as facility_name
       from audit_log a left join facility f on f.id = a.facility_id
      ${whereSql}
      order by a.at desc limit $${params.length}`,
    params
  );
  res.json(rows.map((r) => ({
    id: String(r.id), at: r.at, email: r.user_email, role: r.role,
    action: r.action, module: r.module || null,
    detail: [r.module, r.detail].filter(Boolean).join(" · ") || null,
    facilityId: r.facility_id || null, facilityName: r.facility_name || null,
  })));
}));
 
app.get("/api/health", (req, res) => res.json({ ok: true }));
 
app.listen(PORT, () => console.log(`Eminent Central API (v2) on :${PORT}`));
 
