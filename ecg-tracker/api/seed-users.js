// Creates one corporate login + one per facility. Run: node seed-users.js
import pg from "pg";
import bcrypt from "bcryptjs";
import "dotenv/config";
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const PASSWORDS = {}; // optionally hard-code { "eden@eminentcare.com": "..." }
const rand = () => Math.random().toString(36).slice(2, 6) + "-" + Math.random().toString(36).slice(2, 6);
const slug = (n) => n.toLowerCase().replace(/[^a-z0-9]+/g, "");
async function up(email, role, facilityId, pw) {
  const hash = await bcrypt.hash(pw, 10);
  await pool.query(
    `insert into app_user (email, role, facility_id, password_hash) values ($1,$2,$3,$4)
     on conflict (email) do update set password_hash=excluded.password_hash, role=excluded.role, facility_id=excluded.facility_id`,
    [email, role, facilityId, hash]);
}
async function main() {
  const made = [];
  const admin = "ops@eminentcare.com", apw = PASSWORDS[admin] || rand();
  await up(admin, "admin", null, apw); made.push({ email: admin, role: "admin (manages logins)", password: apw });
  const corp = "corporate@eminentcare.com", cpw = PASSWORDS[corp] || rand();
  await up(corp, "corporate", null, cpw); made.push({ email: corp, role: "corporate (view all)", password: cpw });
  const { rows } = await pool.query("select id, name from facility order by sort_order, name");
  for (const f of rows) {
    const email = `${slug(f.name)}@eminentcare.com`, pw = PASSWORDS[email] || rand();
    await up(email, "facility", f.id, pw); made.push({ email, role: `facility · ${f.name}`, password: pw });
  }
  console.table(made);
  console.log("\nShare each facility login only with that facility. Change passwords after first sign-in.");
  console.log("The admin login manages everyone else from inside the app — no need to re-run this.");
  await pool.end();
}
main().catch((e) => { console.error(e); process.exit(1); });
