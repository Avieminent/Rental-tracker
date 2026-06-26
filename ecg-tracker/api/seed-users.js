// ============================================================
// Creates initial logins: one corporate admin + one user per facility.
// Run after schema.sql + seed.sql:  node seed-users.js
//
// Prints a table of emails and temporary passwords. CHANGE THESE
// after first login (or set your own in the PASSWORDS map below).
// ============================================================
import pg from "pg";
import bcrypt from "bcryptjs";
import "dotenv/config";

const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Optionally hard-code passwords here; otherwise random ones are generated.
const PASSWORDS = {
  // "ops@eminentcare.com": "choose-a-strong-one",
};
const rand = () => Math.random().toString(36).slice(2, 6) + "-" + Math.random().toString(36).slice(2, 6);

async function upsertUser(email, role, facilityId, pw) {
  const hash = await bcrypt.hash(pw, 10);
  await pool.query(
    `insert into app_user (email, role, facility_id, password_hash)
     values ($1,$2,$3,$4)
     on conflict (email) do update set password_hash = excluded.password_hash, role = excluded.role, facility_id = excluded.facility_id`,
    [email, role, facilityId, hash]
  );
}

const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, "");

async function main() {
  const created = [];

  // A — admin: all facilities + portfolio + the login manager
  const adminEmail = "ops@eminentcare.com";
  const adminPw = PASSWORDS[adminEmail] || rand();
  await upsertUser(adminEmail, "admin", null, adminPw);
  created.push({ email: adminEmail, role: "admin (manages logins)", password: adminPw });

  // B — corporate: all facilities + portfolio, but no login manager
  const corpEmail = "corporate@eminentcare.com";
  const corpPw = PASSWORDS[corpEmail] || rand();
  await upsertUser(corpEmail, "corporate", null, corpPw);
  created.push({ email: corpEmail, role: "corporate (view all)", password: corpPw });

  // C — one facility login per facility
  const { rows: facilities } = await pool.query("select id, name from facility order by sort_order, name");
  for (const f of facilities) {
    const email = `${slug(f.name)}@eminentcare.com`;
    const pw = PASSWORDS[email] || rand();
    await upsertUser(email, "facility", f.id, pw);
    created.push({ email, role: `facility · ${f.name}`, password: pw });
  }

  console.table(created);
  console.log("\nDone. Share each facility login only with that facility. Change passwords after first sign-in.");
  console.log("The 'admin' login can add/reset/remove logins from inside the app — no need to run this again.");
  await pool.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
