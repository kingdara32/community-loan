const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const cfg = require('./config');

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DATA_KEY = process.env.DATA_KEY; // 64 hex chars (32 bytes)
if (!JWT_SECRET || !ADMIN_TOKEN || !DATA_KEY || DATA_KEY.length !== 64) {
  console.error('Set JWT_SECRET, ADMIN_TOKEN and DATA_KEY (64 hex chars). See README.');
  process.exit(1);
}
const key = Buffer.from(DATA_KEY, 'hex');
const enc = (t) => { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const b = Buffer.concat([c.update(String(t), 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), b]).toString('base64'); };
const dec = (s) => { const b = Buffer.from(s, 'base64'); const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };

const db = new Database(process.env.DB_FILE || 'loan.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, phone TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  consent_at TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS profiles(user_id INTEGER NOT NULL, section TEXT NOT NULL, data TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id, section));
CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount REAL NOT NULL,
  term_months INTEGER NOT NULL, annual_rate REAL NOT NULL, total REAL NOT NULL, monthly REAL NOT NULL,
  status TEXT DEFAULT 'pending', note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, decided_at TEXT);
CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount REAL NOT NULL,
  status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP, decided_at TEXT);
`);
try { db.exec("ALTER TABLE applications ADD COLUMN order_no TEXT"); } catch (e) {}
// Free-text status staff can set on an application in addition to its real pending/approved/etc. status —
// e.g. "Processing", "Waiting 5 min" — shown as a colored badge. Purely informational, never used by the app logic.
try { db.exec("ALTER TABLE applications ADD COLUMN custom_status TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE applications ADD COLUMN custom_status_color TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN pin_hash TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'enabled'"); } catch (e) {}
try { db.exec("ALTER TABLE users ADD COLUMN level_override INTEGER"); } catch (e) {}
// Once a member submits their profile (ID, personal info, bank account, signature all complete), it's
// locked — they can no longer edit any of those four sections themselves. Staff can still correct a
// locked profile from the admin back office (that uses a separate, admin-only save path).
try { db.exec("ALTER TABLE users ADD COLUMN profile_locked INTEGER DEFAULT 0"); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
// Optional: set ADMIN_USER / ADMIN_PASSWORD env vars to create (or reset the password of) a staff login on boot.
// This is how the first admin account gets in — after that, staff can add more from Admin Users in the back office.
if (process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
  const uname = String(process.env.ADMIN_USER).trim().toLowerCase();
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  const existing = db.prepare('SELECT id FROM admins WHERE username=?').get(uname);
  if (existing) db.prepare('UPDATE admins SET pass_hash=? WHERE id=?').run(hash, existing.id);
  else db.prepare('INSERT INTO admins(username, pass_hash) VALUES(?,?)').run(uname, hash);
}
db.exec(`CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, message TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, read_at TEXT);`);
try { db.exec("ALTER TABLE notifications ADD COLUMN from_admin INTEGER DEFAULT 0"); } catch (e) {}
db.exec(`CREATE TABLE IF NOT EXISTS wallet_adjustments(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, delta REAL NOT NULL,
  note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS login_log(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, ua TEXT);`);
function notify(uid, message, fromAdmin) { db.prepare('INSERT INTO notifications(user_id, message, from_admin) VALUES(?,?,?)').run(uid, message, fromAdmin ? 1 : 0); }
const genOrderNo = () => String(Date.now()) + String(Math.floor(100 + Math.random() * 900));


const UP = path.join(__dirname, 'uploads');
fs.mkdirSync(UP, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({ destination: UP, filename: (r, f, cb) => cb(null, crypto.randomUUID() + '.jpg') }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, /^image\/(jpeg|png)$/.test(f.mimetype)),
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));
app.use('/api/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 20 }));
app.use('/api/admin/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20 }));

const PHONE = /^\+?\d{7,15}$/;
const norm = (p) => String(p || '').replace(/[\s-]/g, '');
const SECTIONS = {
  id: ['name', 'id_no', 'front', 'back', 'selfie'],
  personal: ['company', 'position', 'salary', 'home_address', 'current_address', 'family_name', 'family_rel', 'family_phone', 'emerg_name', 'emerg_rel', 'emerg_phone', 'contacts_ok'],
  bank: ['bank_name', 'holder', 'account_no'],
  signature: ['image'],
};
const SENSITIVE = { id: ['id_no'], bank: ['account_no'] };

function balanceOf(uid) {
  const disbursed = db.prepare("SELECT COALESCE(SUM(total),0) t FROM applications WHERE user_id=? AND status='disbursed'").get(uid).t;
  const taken = db.prepare("SELECT COALESCE(SUM(amount),0) t FROM withdrawals WHERE user_id=? AND status IN ('pending','paid')").get(uid).t;
  const adj = db.prepare("SELECT COALESCE(SUM(delta),0) t FROM wallet_adjustments WHERE user_id=?").get(uid).t;
  return +(disbursed - taken + adj).toFixed(2);
}
// Admin (protect with HTTPS and a strong ADMIN_TOKEN). Declared early: several customer-facing
// routes below (e.g. the admin-only withdrawal-code route) reference it before the old "admin
// section" location further down the file, and JS throws if a const is used before its declaration runs.
const admin = (req, res, next) => {
  const t = req.headers['x-admin-token'];
  if (t && t === ADMIN_TOKEN) return next(); // legacy master key, still works
  try { if (jwt.verify(t, JWT_SECRET).admin === true) return next(); } catch (e) {}
  res.status(401).json({ error: 'Unauthorized' });
};
const auth = (req, res, next) => {
  // Only the token check goes in the try — next() is called outside it, so a real error further down the
  // route (not a bad/missing login token) doesn't get mislabeled as "Please log in again."
  let uid;
  try { uid = jwt.verify((req.headers.authorization || '').slice(7), JWT_SECRET).uid; }
  catch { return res.status(401).json({ error: 'Please log in again.' }); }
  req.uid = uid; next();
};
const token = (uid) => jwt.sign({ uid }, JWT_SECRET, { expiresIn: '7d' });

app.post('/api/register', (req, res) => {
  const { password, consent } = req.body || {};
  const phone = norm(req.body && req.body.phone);
  if (!PHONE.test(phone)) return res.status(400).json({ error: 'Enter a valid phone number (7 to 15 digits).' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (consent !== true) return res.status(400).json({ error: 'You must accept the Privacy Notice to register.' });
  try {
    const r = db.prepare('INSERT INTO users(phone, pass_hash, consent_at) VALUES(?,?,?)')
      .run(phone, bcrypt.hashSync(password, 12), new Date().toISOString());
    notify(r.lastInsertRowid, 'Registration successful. Welcome!');
    res.json({ token: token(r.lastInsertRowid) });
  } catch { res.status(409).json({ error: 'This number is already registered.' }); }
});

app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE phone=?').get(norm(req.body && req.body.phone));
  if (!u || !bcrypt.compareSync(password || '', u.pass_hash)) return res.status(401).json({ error: 'Wrong phone number or password.' });
  if (u.status === 'disabled') return res.status(403).json({ error: 'This account has been disabled. Please contact support.' });
  db.prepare('INSERT INTO login_log(user_id, ua) VALUES(?,?)').run(u.id, String(req.headers['user-agent'] || '').slice(0, 200));
  res.json({ token: token(u.id) });
});

function loadProfile(uid) {
  const out = {};
  for (const r of db.prepare('SELECT section, data FROM profiles WHERE user_id=?').all(uid)) {
    const d = JSON.parse(r.data);
    for (const f of SENSITIVE[r.section] || []) if (d[f]) d[f] = dec(d[f]);
    out[r.section] = d;
  }
  return out;
}
const peso = (n) => '₱' + Number(n || 0).toLocaleString('en-PH', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
// Admin edits to a profile section skip the customer form's "every field required" rule (SECTIONS/
// PUT /api/profile/:section) since this is a correction tool, not the sign-up flow: an admin can fix
// or fill in one field without having every other field on hand. Encrypts sensitive fields same as normal saves.
function adminSaveSection(uid, section, patch) {
  const cur = db.prepare('SELECT data FROM profiles WHERE user_id=? AND section=?').get(uid, section);
  const d = cur ? JSON.parse(cur.data) : {};
  for (const f of SENSITIVE[section] || []) if (d[f]) d[f] = dec(d[f]);
  for (const [k, v] of Object.entries(patch)) if (v !== undefined && v !== null && String(v).length) d[k] = String(v);
  for (const f of SENSITIVE[section] || []) if (d[f]) d[f] = enc(d[f]);
  db.prepare('INSERT INTO profiles(user_id, section, data) VALUES(?,?,?) ON CONFLICT(user_id, section) DO UPDATE SET data=excluded.data, updated_at=CURRENT_TIMESTAMP')
    .run(uid, section, JSON.stringify(d));
}

// Score (1-9, shown to the member as 100-900) is normally just a flat, automatic 5 (500) for everyone —
// it never moves on its own and is never used to gate or upsell anything. Staff correct it by hand
// (users.level_override) when a member should show a different value; that override, when set, simply
// wins over the automatic 5.
function levelOf(profile, apps, override) {
  if (override !== undefined && override !== null) return override;
  return 5;
}
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT phone, pin_hash, level_override, profile_locked FROM users WHERE id=?').get(req.uid);
  const apps = db.prepare('SELECT * FROM applications WHERE user_id=? ORDER BY id DESC').all(req.uid);
  const withdrawals = db.prepare('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(req.uid);
  const profile = loadProfile(req.uid);
  res.json({ phone: u.phone, profile, applications: apps, withdrawals, balance: balanceOf(req.uid),
    hasPin: !!u.pin_hash, level: levelOf(profile, apps, u.level_override), profileLocked: !!u.profile_locked,
    config: { lender: cfg.LENDER_NAME, sec: cfg.SEC_NO, rate: cfg.RATE, min: cfg.MIN_AMOUNT, max: cfg.MAX_AMOUNT, terms: cfg.TERMS, hours: cfg.SUPPORT_HOURS, support: cfg.SUPPORT_URL } });
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Upload a JPG or PNG under 5 MB.' });
  res.json({ file: req.file.filename });
});

app.put('/api/profile/:section', auth, (req, res) => {
  const s = req.params.section, fields = SECTIONS[s];
  if (!fields) return res.status(404).json({ error: 'Unknown section.' });
  const locked = db.prepare('SELECT profile_locked FROM users WHERE id=?').get(req.uid);
  if (locked && locked.profile_locked) return res.status(403).json({ error: 'Your profile is submitted and can no longer be edited. Contact support if something needs to change.' });
  const d = {};
  for (const f of fields) {
    const v = String((req.body || {})[f] ?? '').trim();
    if (!v) return res.status(400).json({ error: 'Please complete every field.' });
    d[f] = v;
  }
  if (s === 'personal' && d.contacts_ok !== 'yes') return res.status(400).json({ error: 'Please confirm your contacts agreed to be listed.' });
  // Bank account holder no longer has to match the member's own ID name — members may disburse to a
  // relative's or another trusted person's account. The account holder name they type is still stored and
  // shown to admin/staff as-is, so who actually owns the account stays visible on the back office.
  for (const f of ['front', 'back', 'selfie']) if (d[f] && !/^[\w-]+\.jpg$/.test(d[f])) return res.status(400).json({ error: 'Invalid file.' });
  if (s === 'signature' && !/^data:image\/png;base64,/.test(d.image)) return res.status(400).json({ error: 'Invalid signature.' });
  for (const f of SENSITIVE[s] || []) d[f] = enc(d[f]);
  db.prepare('INSERT INTO profiles(user_id, section, data) VALUES(?,?,?) ON CONFLICT(user_id, section) DO UPDATE SET data=excluded.data, updated_at=CURRENT_TIMESTAMP')
    .run(req.uid, s, JSON.stringify(d));
  res.json({ ok: true });
});

// Locks the profile once all four sections are complete, so the member can't come back and edit their
// ID, personal info, bank account or signature afterward. Staff can still fix a locked profile from the
// admin back office (Checking data), which uses its own save path and ignores this lock.
app.post('/api/profile/submit', auth, (req, res) => {
  const profile = loadProfile(req.uid);
  if (!['id', 'personal', 'bank', 'signature'].every((k) => profile[k])) return res.status(400).json({ error: 'Please complete all four steps first.' });
  db.prepare('UPDATE users SET profile_locked=1 WHERE id=?').run(req.uid);
  res.json({ ok: true });
});
app.post('/api/apply', auth, (req, res) => {
  const amount = Number(req.body.amount), term = Number(req.body.term);
  const p = loadProfile(req.uid);
  if (!['id', 'personal', 'bank', 'signature'].every((k) => p[k])) return res.status(400).json({ error: 'Complete your profile first.' });
  if (!(amount >= cfg.MIN_AMOUNT && amount <= cfg.MAX_AMOUNT) || !cfg.TERMS.includes(term)) return res.status(400).json({ error: 'Choose a valid amount and term.' });
  if (db.prepare("SELECT 1 FROM applications WHERE user_id=? AND status IN ('pending','approved')").get(req.uid))
    return res.status(409).json({ error: 'You already have an open application.' });
  const total = +(amount * (1 + (cfg.RATE / 100) * term)).toFixed(2);
  const monthly = +(total / term).toFixed(2);
  db.prepare('INSERT INTO applications(user_id, amount, term_months, annual_rate, total, monthly, order_no) VALUES(?,?,?,?,?,?,?)')
    .run(req.uid, amount, term, cfg.RATE, total, monthly, genOrderNo());
  notify(req.uid, 'Your application is under review.');
  res.json({ ok: true });
});

// Withdrawal PIN: the user sets this themselves in Settings. The backend stores only a hash and
// checks withdrawals against it — nothing is sent to a phone, and nothing can be bought or unlocked.
// The withdrawal code is set only by staff, from the admin page — never by the customer in the app.
app.put('/api/admin/pin', admin, (req, res) => {
  const phone = norm(req.body && req.body.phone);
  const pin = String((req.body && req.body.pin) || '').trim();
  if (!/^\d{4,6}$/.test(pin)) return res.status(400).json({ error: 'Use a code of 4 to 6 digits.' });
  const u = db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
  if (!u) return res.status(404).json({ error: 'No user with that phone number.' });
  db.prepare('UPDATE users SET pin_hash=? WHERE id=?').run(bcrypt.hashSync(pin, 10), u.id);
  // No automatic notification here by design — staff tell the member the new code themselves
  // (e.g. via the Notifications page), since auto-notifications are limited to register/apply/approved.
  res.json({ ok: true });
});

// ---- Member back office: search/list, full detail, and the per-field correction tools ----
function memberRow(u) {
  const idSec = db.prepare("SELECT data FROM profiles WHERE user_id=? AND section='id'").get(u.id);
  let name = '';
  if (idSec) { try { name = JSON.parse(idSec.data).name || ''; } catch {} }
  const notes = db.prepare('SELECT note FROM wallet_adjustments WHERE user_id=? ORDER BY id DESC LIMIT 3').all(u.id);
  const apps = db.prepare('SELECT status FROM applications WHERE user_id=?').all(u.id);
  const profile = loadProfile(u.id);
  return {
    id: u.id, phone: u.phone, name, status: u.status || 'enabled', hasPin: !!u.pin_hash,
    balance: balanceOf(u.id), created_at: u.created_at, note: notes.map((n) => n.note).join(' | '),
    level: levelOf(profile, apps, u.level_override), levelOverridden: u.level_override !== null && u.level_override !== undefined,
  };
}
// Staff log in with a username/password (set the first one via ADMIN_USER/ADMIN_PASSWORD env vars) instead of
// sharing the master ADMIN_TOKEN. Successful login returns a 12-hour token used the same way ADMIN_TOKEN was.
app.post('/api/admin/login', (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = (req.body && req.body.password) || '';
  const row = username && db.prepare('SELECT * FROM admins WHERE username=?').get(username);
  if (!row || !bcrypt.compareSync(password, row.pass_hash)) return res.status(401).json({ error: 'Wrong username or password.' });
  res.json({ token: jwt.sign({ admin: true, sub: username }, JWT_SECRET, { expiresIn: '12h' }) });
});
// Manage staff logins (admin-only). A logged-in admin can add teammates or remove access without touching env vars.
app.get('/api/admin/admins', admin, (req, res) => {
  res.json(db.prepare('SELECT id, username, created_at FROM admins ORDER BY id').all());
});
app.post('/api/admin/admins', admin, (req, res) => {
  const username = String((req.body && req.body.username) || '').trim().toLowerCase();
  const password = (req.body && req.body.password) || '';
  if (!/^[a-z0-9._-]{3,40}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-40 characters: letters, numbers, dot, underscore or dash.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const hash = bcrypt.hashSync(password, 12);
  const existing = db.prepare('SELECT id FROM admins WHERE username=?').get(username);
  if (existing) db.prepare('UPDATE admins SET pass_hash=? WHERE id=?').run(hash, existing.id);
  else db.prepare('INSERT INTO admins(username, pass_hash) VALUES(?,?)').run(username, hash);
  res.json({ ok: true });
});
app.delete('/api/admin/admins/:id', admin, (req, res) => {
  if (db.prepare('SELECT COUNT(*) c FROM admins').get().c <= 1) return res.status(400).json({ error: 'Cannot remove the last admin login.' });
  db.prepare('DELETE FROM admins WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/members', admin, (req, res) => {
  const q = norm(req.query && req.query.q || '').toLowerCase();
  let rows = db.prepare('SELECT id, phone, status, pin_hash, level_override, created_at FROM users ORDER BY id DESC').all().map(memberRow);
  if (q) rows = rows.filter((r) => r.phone.toLowerCase().includes(q) || r.name.toLowerCase().includes((req.query.q || '').toLowerCase()));
  res.json(rows);
});
app.get('/api/admin/members/:id', admin, (req, res) => {
  const uid = +req.params.id;
  const u = db.prepare('SELECT id, phone, status, pin_hash, level_override, created_at FROM users WHERE id=?').get(uid);
  if (!u) return res.status(404).json({ error: 'Member not found.' });
  const adjustments = db.prepare('SELECT * FROM wallet_adjustments WHERE user_id=? ORDER BY id DESC LIMIT 20').all(uid);
  const apps = db.prepare('SELECT status FROM applications WHERE user_id=?').all(uid);
  const profile = loadProfile(uid);
  res.json({ id: u.id, phone: u.phone, status: u.status || 'enabled', hasPin: !!u.pin_hash,
    created_at: u.created_at, profile, balance: balanceOf(uid), adjustments,
    level: levelOf(profile, apps, u.level_override), levelOverridden: u.level_override !== null && u.level_override !== undefined });
});
app.get('/api/admin/members/:id/logins', admin, (req, res) => {
  res.json(db.prepare('SELECT created_at, ua FROM login_log WHERE user_id=? ORDER BY id DESC LIMIT 50').all(+req.params.id));
});
app.put('/api/admin/members/:id/checking', admin, (req, res) => {
  const uid = +req.params.id;
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  const body = req.body || {};
  for (const section of ['id', 'personal', 'bank']) {
    if (body[section] && typeof body[section] === 'object') adminSaveSection(uid, section, body[section]);
  }
  res.json({ ok: true });
});
app.post('/api/admin/members/:id/photo-delete', admin, (req, res) => {
  const uid = +req.params.id;
  const section = req.body && req.body.section, field = req.body && req.body.field;
  if (!['id', 'signature'].includes(section)) return res.status(400).json({ error: 'Bad section.' });
  const cur = db.prepare('SELECT data FROM profiles WHERE user_id=? AND section=?').get(uid, section);
  if (!cur) return res.status(404).json({ error: 'Not found.' });
  const d = JSON.parse(cur.data);
  if (section === 'id' && d[field] && /^[\w-]+\.jpg$/.test(d[field])) { try { fs.unlinkSync(path.join(UP, d[field])); } catch {} }
  delete d[field];
  db.prepare('UPDATE profiles SET data=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=? AND section=?').run(JSON.stringify(d), uid, section);
  res.json({ ok: true });
});
app.put('/api/admin/members/:id/identity', admin, (req, res) => {
  const uid = +req.params.id;
  const id_no = String((req.body && req.body.id_no) || '').trim(), name = String((req.body && req.body.name) || '').trim();
  if (!id_no || !name) return res.status(400).json({ error: 'Enter the ID number and name.' });
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  adminSaveSection(uid, 'id', { id_no, name });
  res.json({ ok: true });
});
app.put('/api/admin/members/:id/bank', admin, (req, res) => {
  const uid = +req.params.id;
  const bank_name = String((req.body && req.body.bank_name) || '').trim();
  const holder = String((req.body && req.body.holder) || '').trim();
  const account_no = String((req.body && req.body.account_no) || '').trim();
  if (!bank_name || !holder || !account_no) return res.status(400).json({ error: 'Complete all bank fields.' });
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  adminSaveSection(uid, 'bank', { bank_name, holder, account_no });
  res.json({ ok: true });
});
app.put('/api/admin/members/:id/password', admin, (req, res) => {
  const uid = +req.params.id;
  const pw = String((req.body && req.body.password) || '');
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const r = db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(bcrypt.hashSync(pw, 12), uid);
  if (!r.changes) return res.status(404).json({ error: 'Member not found.' });
  // No automatic notification — staff message the member directly if they want to, from Notifications.
  res.json({ ok: true });
});
app.put('/api/admin/members/:id/pin', admin, (req, res) => {
  const uid = +req.params.id;
  const pin = String((req.body && req.body.pin) || '').trim();
  if (!/^\d{4,6}$/.test(pin)) return res.status(400).json({ error: 'Use a code of 4 to 6 digits.' });
  const r = db.prepare('UPDATE users SET pin_hash=? WHERE id=?').run(bcrypt.hashSync(pin, 10), uid);
  if (!r.changes) return res.status(404).json({ error: 'Member not found.' });
  // No automatic notification — the withdrawal code is one-time use (see /api/withdraw), so staff tell the
  // member the new code themselves each time it's reset, from the Notifications page.
  res.json({ ok: true });
});
app.put('/api/admin/members/:id/status', admin, (req, res) => {
  const uid = +req.params.id;
  const status = req.body && req.body.status;
  if (!['enabled', 'disabled'].includes(status)) return res.status(400).json({ error: 'Bad status.' });
  const r = db.prepare('UPDATE users SET status=? WHERE id=?').run(status, uid);
  if (!r.changes) return res.status(404).json({ error: 'Member not found.' });
  res.json({ ok: true });
});
// Level is normally computed from real activity (see levelOf). This lets staff correct it by hand when
// the computed value is wrong — send level: null (or omit it) to clear the override and go back to automatic.
app.put('/api/admin/members/:id/level', admin, (req, res) => {
  const uid = +req.params.id;
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  const raw = req.body && req.body.level;
  let val = null;
  if (raw !== null && raw !== undefined && raw !== '') {
    val = Number(raw);
    if (!Number.isInteger(val) || val < 1 || val > 9) return res.status(400).json({ error: 'Score must be 100 to 900.' });
  }
  db.prepare('UPDATE users SET level_override=? WHERE id=?').run(val, uid);
  res.json({ ok: true, level: val });
});
// Wallet is otherwise computed only from real disbursed loans minus real withdrawals (balanceOf) — this
// lets staff record a manual correction (a data-entry fix, an off-system disbursement) as an auditable
// delta rather than a number typed over the real ledger, and every change is logged with who/when.
app.put('/api/admin/members/:id/wallet', admin, (req, res) => {
  const uid = +req.params.id;
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  const newBalance = Number(req.body && req.body.balance);
  if (!Number.isFinite(newBalance) || newBalance < 0) return res.status(400).json({ error: 'Enter a valid amount.' });
  const cur = balanceOf(uid);
  const delta = +(newBalance - cur).toFixed(2);
  if (delta !== 0) {
    const note = `Update wallet from ${peso(cur)} to ${peso(newBalance)} on ${new Date().toISOString().slice(0, 10)} by Admin`;
    db.prepare('INSERT INTO wallet_adjustments(user_id, delta, note) VALUES(?,?,?)').run(uid, delta, note);
    // No automatic notification — staff tell the member if needed, from Notifications.
  }
  res.json({ ok: true, balance: newBalance });
});
app.get('/api/admin/stats', admin, (req, res) => {
  res.json({
    members: db.prepare('SELECT COUNT(*) c FROM users').get().c,
    pendingLoans: db.prepare("SELECT COUNT(*) c FROM applications WHERE status='pending'").get().c,
    pendingWithdrawals: db.prepare("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").get().c,
    totalLoans: db.prepare('SELECT COUNT(*) c FROM applications').get().c,
  });
});
app.get('/api/notifications', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.uid);
  const unread = db.prepare("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND read_at IS NULL").get(req.uid).c;
  res.json({ items: rows, unread });
});
app.post('/api/notifications/read', auth, (req, res) => {
  db.prepare("UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE user_id=? AND read_at IS NULL").run(req.uid);
  res.json({ ok: true });
});
app.post('/api/withdraw', auth, (req, res) => {
  const amount = Number(req.body && req.body.amount);
  const pin = String((req.body && req.body.pin) || '').trim();
  const u = db.prepare('SELECT pin_hash FROM users WHERE id=?').get(req.uid);
  if (!(amount > 0)) return res.status(400).json({ error: 'Enter an amount greater than zero.' });
  if (amount > balanceOf(req.uid)) return res.status(400).json({ error: 'That is more than your available balance.' });
  if (!u.pin_hash) return res.status(400).json({ error: "Your withdrawal code isn't set up yet. Check your notifications, or contact support." });
  if (!bcrypt.compareSync(pin, u.pin_hash)) return res.status(400).json({ error: 'That withdrawal code is wrong.' });
  if (db.prepare("SELECT 1 FROM withdrawals WHERE user_id=? AND status='pending'").get(req.uid))
    return res.status(409).json({ error: 'You already have a withdrawal request being processed.' });
  db.prepare('INSERT INTO withdrawals(user_id, amount) VALUES(?,?)').run(req.uid, amount);
  // The withdrawal code is single-use: once it's been used to submit a request, clear it so the same code
  // can't be reused. Staff set a fresh one (Members → Withdrawal Code) before the member's next withdrawal.
  db.prepare('UPDATE users SET pin_hash=? WHERE id=?').run(null, req.uid);
  res.json({ ok: true });
});

app.get('/api/admin/withdrawals', admin, (req, res) => {
  const rows = db.prepare('SELECT w.*, u.phone FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC').all();
  res.json(rows);
});
app.post('/api/admin/withdrawals/:id/decision', admin, (req, res) => {
  const status = req.body && req.body.status;
  if (!['paid', 'rejected', 'failed'].includes(status)) return res.status(400).json({ error: 'Bad status' });
  db.prepare('UPDATE withdrawals SET status=?, decided_at=CURRENT_TIMESTAMP WHERE id=?').run(status, req.params.id);
  // No automatic notification — staff tell the member if needed, from Notifications.
  res.json({ ok: true });
});
app.post('/api/admin/notify', admin, (req, res) => {
  const phone = norm(req.body && req.body.phone);
  const message = String((req.body && req.body.message) || '').trim();
  if (!message) return res.status(400).json({ error: 'Message is empty.' });
  const u = db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
  if (!u) return res.status(404).json({ error: 'No user with that phone number.' });
  notify(u.id, message, true);
  res.json({ ok: true });
});
// Same as above but by member id, and a broadcast variant — used by the Notifications page in the
// new admin back office, which searches members by name/phone instead of asking staff to type the number.
app.post('/api/admin/members/:id/notify', admin, (req, res) => {
  const uid = +req.params.id;
  const message = String((req.body && req.body.message) || '').trim();
  if (!message) return res.status(400).json({ error: 'Message is empty.' });
  if (!db.prepare('SELECT id FROM users WHERE id=?').get(uid)) return res.status(404).json({ error: 'Member not found.' });
  notify(uid, message, true);
  res.json({ ok: true });
});
app.post('/api/admin/notify-all', admin, (req, res) => {
  const message = String((req.body && req.body.message) || '').trim();
  if (!message) return res.status(400).json({ error: 'Message is empty.' });
  const users = db.prepare('SELECT id FROM users').all();
  const insert = db.prepare('INSERT INTO notifications(user_id, message, from_admin) VALUES(?,?,1)');
  db.transaction((list) => { for (const u of list) insert.run(u.id, message); })(users);
  res.json({ ok: true, count: users.length });
});
app.get('/api/admin/notifications', admin, (req, res) => {
  res.json(db.prepare('SELECT n.*, u.phone FROM notifications n JOIN users u ON u.id=n.user_id ORDER BY n.id DESC LIMIT 300').all());
});
app.get('/api/admin/applications', admin, (req, res) => {
  const rows = db.prepare('SELECT a.*, u.phone FROM applications a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC').all();
  res.json(rows.map((r) => ({ ...r, profile: loadProfile(r.user_id) })));
});
const STATUS_MSG = {
  approved: 'Your loan has been approved.',
  disbursed: 'Your loan has been sent to your bank account on file.',
  completed: 'Your loan has been fully repaid. Thank you!',
  rejected: 'Your application was not approved this time.',
};
app.post('/api/admin/applications/:id/decision', admin, (req, res) => {
  const { status, note } = req.body || {};
  if (!['approved', 'rejected', 'disbursed', 'completed'].includes(status)) return res.status(400).json({ error: 'Bad status' });
  db.prepare('UPDATE applications SET status=?, note=?, decided_at=CURRENT_TIMESTAMP WHERE id=?').run(status, note || '', req.params.id);
  // Auto-notifications are limited to register / apply / approved — only send one here for "approved".
  // For rejected/disbursed/completed, staff send a message themselves from Notifications if they want to.
  if (status === 'approved') {
    const row = db.prepare('SELECT user_id FROM applications WHERE id=?').get(req.params.id);
    if (row) notify(row.user_id, STATUS_MSG[status] + (note ? ' ' + note : ''));
  }
  res.json({ ok: true });
});
// Modify Loan: staff correct the amount/term on an application still under review (a typo, a re-negotiated
// amount) — recomputes total/monthly from the same flat-rate formula apply() uses, so figures stay consistent.
app.put('/api/admin/applications/:id', admin, (req, res) => {
  const id = +req.params.id;
  const amount = Number(req.body && req.body.amount), term = Number(req.body && req.body.term_months);
  if (!(amount > 0) || !(term > 0)) return res.status(400).json({ error: 'Enter a valid amount and term.' });
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(id);
  if (!a) return res.status(404).json({ error: 'Application not found.' });
  const total = +(amount * (1 + (a.annual_rate / 100) * term)).toFixed(2);
  const monthly = +(total / term).toFixed(2);
  db.prepare('UPDATE applications SET amount=?, term_months=?, total=?, monthly=? WHERE id=?').run(amount, term, total, monthly, id);
  // No automatic notification — staff tell the member if needed, from Notifications.
  res.json({ ok: true });
});
// Lets staff set a free-text status note on a loan application (e.g. "Processing", "Waiting 5 min") shown as a
// colored badge in the Borrowing List — purely informational, independent of the real pending/approved/etc. status.
app.put('/api/admin/applications/:id/custom-status', admin, (req, res) => {
  const id = +req.params.id;
  if (!db.prepare('SELECT id FROM applications WHERE id=?').get(id)) return res.status(404).json({ error: 'Application not found.' });
  const text = String((req.body && req.body.text) || '').trim().slice(0, 60);
  const colorIn = (req.body && req.body.color) || '';
  const color = ['red', 'green'].includes(colorIn) ? colorIn : 'blue';
  db.prepare('UPDATE applications SET custom_status=?, custom_status_color=? WHERE id=?').run(text || null, text ? color : null, id);
  res.json({ ok: true });
});
app.delete('/api/admin/applications/:id', admin, (req, res) => {
  const r = db.prepare('DELETE FROM applications WHERE id=?').run(+req.params.id);
  res.json({ ok: !!r.changes });
});
app.get('/api/admin/file/:name', admin, (req, res) => {
  if (!/^[\w-]+\.jpg$/.test(req.params.name)) return res.sendStatus(400);
  res.sendFile(path.join(UP, req.params.name));
});
// Lets a member view their own uploaded ID photos (front/back/selfie) back — not any other file, and not
// anyone else's. Same file storage as the admin-only route above, just scoped to the caller's own profile.
app.get('/api/file/:name', auth, (req, res) => {
  if (!/^[\w-]+\.jpg$/.test(req.params.name)) return res.sendStatus(400);
  const idProfile = loadProfile(req.uid).id || {};
  const owns = ['front', 'back', 'selfie'].some((k) => idProfile[k] === req.params.name);
  if (!owns) return res.sendStatus(403);
  res.sendFile(path.join(UP, req.params.name));
});

app.listen(process.env.PORT || 3000, () => console.log('Running on http://localhost:' + (process.env.PORT || 3000)));
