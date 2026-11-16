'use strict';
/**
 * CortenCloud backend
 * - Express serves /public and the JSON API
 * - Whole app state lives in ONE JSON document (row id=1 in Postgres, or data/db.json locally)
 * - Passwords are hashed (scrypt); sessions are signed tokens
 */
const express = require('express');
const compression = require('compression');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || '';

/* ---------- secrets ---------- */
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  if (DATABASE_URL) { console.error('SESSION_SECRET is required in production.'); process.exit(1); }
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[dev] SESSION_SECRET not set - using a random one (logins reset on restart).');
}
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  if (DATABASE_URL) { console.error('ADMIN_PASSWORD is required in production.'); process.exit(1); }
  ADMIN_PASSWORD = 'admin12345';
  console.warn('[dev] ADMIN_PASSWORD not set - using "admin12345".');
}

/* ---------- helpers ---------- */
class ApiError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const arr = (x) => (Array.isArray(x) ? x : []);
const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);
const uidSrv = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const BOT_STATUSES = ['off', 'starting', 'restarting', 'active', 'stopped', 'expired'];
// statuses a customer may set on its OWN bots (admin grants 'active' / 'stopped')
const CUST_BOT_STATUSES = ['off', 'starting', 'restarting'];

function stable(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort()
    .map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
}

function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verifyPw(pw, stored) {
  if (!stored || typeof pw !== 'string') return false;
  const [s, h] = stored.split(':');
  const hb = Buffer.from(h, 'hex');
  const hh = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
  return hb.length === hh.length && crypto.timingSafeEqual(hh, hb);
}
const b64 = (s) => Buffer.from(s).toString('base64url');
function signToken(nick) {
  const body = b64(JSON.stringify({ n: nick, e: Date.now() + 30 * 24 * 3600 * 1000 }));
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}
function readToken(tok) {
  if (typeof tok !== 'string' || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.e > Date.now() ? p.n : null;
  } catch { return null; }
}

/* ---------- storage ---------- */
function emptyDoc() {
  return {
    rev: 1,
    users: {},
    shared: {
      earned: 0, card: '8600 1234 5678 9012', promos: {}, tariffs: [], botTemplates: [],
      notifs: [], broadcasts: [], adminLogs: [], fileUploads: []
    }
  };
}

function makeStore() {
  const store = { rev: 0 };
  if (DATABASE_URL) {
    const { Pool } = require('pg');
    const local = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
    const pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: (local || process.env.PGSSL === 'disable') ? false : { rejectUnauthorized: false },
      max: 5
    });
    store.init = async () => {
      await pool.query('CREATE TABLE IF NOT EXISTS kv (id int PRIMARY KEY, doc jsonb NOT NULL)');
      await pool.query('INSERT INTO kv(id, doc) VALUES (1, $1) ON CONFLICT (id) DO NOTHING', [JSON.stringify(emptyDoc())]);
      const r = await pool.query('SELECT doc FROM kv WHERE id=1');
      store.rev = r.rows[0].doc.rev || 1;
    };
    store.read = async () => (await pool.query('SELECT doc FROM kv WHERE id=1')).rows[0].doc;
    store.tx = async (fn) => {
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        const doc = (await c.query('SELECT doc FROM kv WHERE id=1 FOR UPDATE')).rows[0].doc;
        const before = doc.rev;
        const out = await fn(doc);
        if (doc.rev !== before) await c.query('UPDATE kv SET doc=$1 WHERE id=1', [JSON.stringify(doc)]);
        await c.query('COMMIT');
        store.rev = doc.rev;
        return out;
      } catch (e) { try { await c.query('ROLLBACK'); } catch {} throw e; }
      finally { c.release(); }
    };
  } else {
    const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
    const file = path.join(dir, 'db.json');
    let mem = null;
    let chain = Promise.resolve();
    store.init = async () => {
      fs.mkdirSync(dir, { recursive: true });
      mem = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : emptyDoc();
      store.rev = mem.rev || 1;
    };
    store.read = async () => mem;
    store.tx = (fn) => {
      const run = async () => {
        const doc = JSON.parse(JSON.stringify(mem));
        const before = doc.rev;
        const out = await fn(doc);
        if (doc.rev !== before) {
          fs.writeFileSync(file + '.tmp', JSON.stringify(doc));
          fs.renameSync(file + '.tmp', file);
          mem = doc; store.rev = doc.rev;
        }
        return out;
      };
      const p = chain.then(run, run);
      chain = p.catch(() => {});
      return p;
    };
  }
  return store;
}
const store = makeStore();
const touch = (doc) => { doc.rev = (doc.rev || 0) + 1; };

/* ---------- views ---------- */
const publicUser = (u) => { const o = Object.assign({}, u); delete o.passHash; return o; };
function viewFor(doc, nick) {
  const s = doc.shared;
  const me = nick && has(doc.users, nick) ? doc.users[nick] : null;
  if (!me) return { shared: { tariffs: s.tariffs, botTemplates: (s.botTemplates || []).filter(t => t.active !== false) } };
  if (me.isAdmin) {
    const users = {};
    Object.keys(doc.users).forEach((k) => { users[k] = publicUser(doc.users[k]); });
    return {
      me: nick, users,
      shared: {
        earned: s.earned, card: s.card, promos: s.promos, tariffs: s.tariffs, botTemplates: s.botTemplates, notifs: s.notifs,
        broadcasts: s.broadcasts, adminLogs: s.adminLogs, fileUploads: s.fileUploads
      }
    };
  }
  return {
    me: nick, users: { [nick]: publicUser(me) },
    shared: { card: s.card, tariffs: s.tariffs, botTemplates: (s.botTemplates || []).filter(t => t.active !== false), notifs: s.notifs, promos: s.promos }
  };
}
const reply = (doc, nick, extra) => Object.assign({ rev: doc.rev, data: viewFor(doc, nick) }, extra || {});

/* ---------- merge rules ---------- */
function unionList(a, b, cap) {
  const seen = new Set(); const out = [];
  for (const x of arr(a).concat(arr(b))) {
    if (!isObj(x)) continue;
    const k = stable(x);
    if (k.length > 4000 || seen.has(k)) continue;
    seen.add(k); out.push(x);
  }
  out.sort((p, q) => (q.time || 0) - (p.time || 0));
  return out.slice(0, cap);
}

function mergeUser(srv, inc, role, doc) {
  if (!isObj(inc)) return;
  const mine = role === 'admin' ? 'admin' : 'user';

  // chat messages: union; each side can only write its own messages
  srv.messages = arr(srv.messages);
  const idx = new Map();
  const mk = (from, time, text) => from + '|' + time + '|' + text;
  srv.messages.forEach((m) => idx.set(mk(m.from, m.time, m.text), m));
  for (const m of arr(inc.messages)) {
    if (!isObj(m) || typeof m.text !== 'string' || (m.from !== 'user' && m.from !== 'admin')) continue;
    const text = m.text.slice(0, 2000);
    const time = Number(m.time) || Date.now();
    const ex = idx.get(mk(m.from, time, text));
    if (ex) { if (m.read === true && ex.from !== mine) ex.read = true; }
    else if (m.from === mine && text.trim()) {
      const nm = { from: mine, text, time, read: false };
      srv.messages.push(nm); idx.set(mk(mine, time, text), nm);
    }
  }
  srv.messages.sort((a, b) => a.time - b.time);
  if (srv.messages.length > 500) srv.messages = srv.messages.slice(-500);

  // top-up requests: customer creates, admin decides (server applies the money)
  srv.topupRequests = arr(srv.topupRequests);
  const byId = new Map(srv.topupRequests.map((r) => [r.id, r]));
  for (const r of arr(inc.topupRequests)) {
    if (!isObj(r) || typeof r.id !== 'string') continue;
    const ex = byId.get(r.id);
    if (!ex) {
      if (role !== 'customer') continue;
      const amount = Math.floor(Number(r.amount));
      if (!(amount >= 5000 && amount <= 1e9)) continue;
      if (typeof r.receipt !== 'string' || r.receipt.length > 4e6) continue;
      const nr = { id: r.id.slice(0, 40), amount, receipt: r.receipt, status: 'pending', time: Number(r.time) || Date.now() };
      srv.topupRequests.push(nr); byId.set(nr.id, nr);
    } else if (role === 'admin' && ex.status === 'pending') {
      if (r.status === 'approved') {
        ex.status = 'approved';
        srv.balance = (srv.balance || 0) + ex.amount;
        doc.shared.earned = (doc.shared.earned || 0) + ex.amount;
      } else if (r.status === 'rejected') {
        ex.status = 'rejected'; ex.receipt = '__stripped__';
      }
    }
  }
  if (srv.topupRequests.length > 200) srv.topupRequests = srv.topupRequests.slice(-200);

  srv.transactions = unionList(srv.transactions, inc.transactions, 120);
  srv.activity = unionList(srv.activity, inc.activity, 60);
  srv.readNotifs = Array.from(new Set(arr(srv.readNotifs).concat(arr(inc.readNotifs).filter((x) => typeof x === 'string')))).slice(-300);

  if (role === 'customer') {
    // 1 TARIFF = 1 BOT (server-side enforcement):
    // A customer CANNOT add new bots through /api/sync. Bots are created only via
    // /api/create-bot, which charges the balance for one tariff. Here we only allow
    // updating mutable fields of bots that already exist (matched by id).
    const incoming = arr(inc.bots).filter(isObj);
    const byIdIn = new Map(incoming.map((b) => [b.id, b]));
    const orig = arr(srv.bots);
    const kept = [];
    const seenIds = new Set();
    for (const sb of orig) {
      const id = String(sb.id || '');
      const inc2 = id && byIdIn.get(id);
      if (!inc2) { kept.push(sb); continue; }        // not in incoming -> keep as-is
      seenIds.add(id);
      // mutable, customer-controlled fields only
      if (typeof inc2.name === 'string' && inc2.name.trim().length >= 2) sb.name = inc2.name.trim().slice(0, 80);
      if (inc2.mainFile === null || (typeof inc2.mainFile === 'string' && inc2.mainFile.length <= 200)) sb.mainFile = inc2.mainFile;
      if (Array.isArray(inc2.files)) {
        sb.files = inc2.files
          .filter((f) => isObj(f) && typeof f.name === 'string' && f.name.length <= 200)
          .slice(0, 50)
          .map((f) => ({ name: String(f.name).slice(0, 200), size: Number(f.size) || 0 }));
      }
      if (Array.isArray(inc2.logs)) {
        // union server + incoming logs by (time,msg,kind) so server-added logs are never lost
        const merged = []; const seen = new Set();
        for (const l of arr(sb.logs).concat(inc2.logs.filter(isObj))) {
          const k = (Number(l.time) || 0) + '|' + String(l.msg || '').slice(0, 200) + '|' + String(l.kind || '');
          if (seen.has(k)) continue; seen.add(k); merged.push(l);
        }
        merged.sort((a, b) => (a.time || 0) - (b.time || 0));
        sb.logs = merged.slice(-120);
      }
      // customer may only request transitional statuses; 'active'/'stopped' are admin-granted
      if (typeof inc2.status === 'string' && CUST_BOT_STATUSES.includes(inc2.status)) sb.status = inc2.status;
      // tariffId / tariffName / price / days / expiresAt / createdAt are IMMUTABLE by customer
      kept.push(sb);
    }
    // any incoming bot id that does not match an existing server bot is DROPPED (no free bots)
    srv.bots = kept.slice(0, 50);

    // CortenBots: customer may only append logs and rename; status is controlled via
    // /api/cb-toggle, creation via /api/cb-create. Unknown incoming ids are dropped.
    srv.cbBots = arr(srv.cbBots);
    const cbIn = arr(inc.cbBots).filter(isObj);
    const cbByIdIn = new Map(cbIn.filter((b) => typeof b.id === 'string').map((b) => [String(b.id), b]));
    srv.cbBots = srv.cbBots.map((sb) => {
      const inc2 = cbByIdIn.get(String(sb.id));
      if (!inc2) return sb;
      if (typeof inc2.name === 'string' && inc2.name.trim().length >= 2) sb.name = inc2.name.trim().slice(0, 80);
      if (Array.isArray(inc2.logs)) {
        const merged = []; const seen = new Set();
        for (const l of arr(sb.logs).concat(inc2.logs.filter(isObj))) {
          const k = (Number(l.time) || 0) + '|' + String(l.msg || '').slice(0, 200) + '|' + String(l.kind || '');
          if (seen.has(k)) continue; seen.add(k); merged.push(l);
        }
        merged.sort((a, b) => (a.time || 0) - (b.time || 0));
        sb.logs = merged.slice(-120);
      }
      return sb;
    });
  } else if (role === 'admin') {
    // manual balance adjustment made by admin (delta, not absolute)
    const d = Math.trunc(Number(inc._dBal));
    if (Number.isFinite(d) && d !== 0 && Math.abs(d) <= 1e12) {
      srv.balance = Math.max(0, (srv.balance || 0) + d);
      doc.shared.earned = Math.max(0, (doc.shared.earned || 0) + d);
    }
    // admin may set bot status (approve -> 'active', stop -> 'stopped', etc.) and delete bots
    if (Array.isArray(inc.bots)) {
      const incoming = inc.bots.filter(isObj);
      const inIds = new Set(incoming.map((b) => String(b.id || '')).filter(Boolean));
      // if admin sends a bots array, treat it as the desired set: keep matched, drop the rest (delete)
      // but only when the admin explicitly sent a bots list (length may be smaller than server's)
      const wantDelete = incoming.some((b) => b._deleted === true);
      srv.bots = arr(srv.bots).filter((sb) => {
        const id = String(sb.id || '');
        if (wantDelete && incoming.find((b) => String(b.id || '') === id && b._deleted)) return false;
        return true;
      });
      // apply status updates from admin onto surviving bots
      arr(srv.bots).forEach((sb) => {
        const id = String(sb.id || '');
        const inc2 = incoming.find((b) => String(b.id || '') === id);
        if (inc2 && typeof inc2.status === 'string' && BOT_STATUSES.includes(inc2.status)) {
          sb.status = inc2.status;
          // extend expiry when admin re-activates a bot that had expired
          if (inc2.status === 'active' && isExpiredBot(sb)) {
            sb.expiresAt = Date.now() + (Number(sb.days) || 30) * 86400000;
          }
        }
      });
    }
    // CortenBots admin moderation: admin may delete a cbBot or force its status (on/off/expired).
    if (Array.isArray(inc.cbBots)) {
      const cbIn = inc.cbBots.filter(isObj);
      const wantDel = cbIn.some((b) => b._deleted === true);
      Object.values(doc.users).forEach((u) => {
        arr(u.cbBots).forEach((sb) => {
          const inc2 = cbIn.find((b) => String(b.id) === String(sb.id));
          if (inc2 && typeof inc2.status === 'string' && ['on', 'off', 'expired'].includes(inc2.status)) sb.status = inc2.status;
        });
        if (wantDel) u.cbBots = arr(u.cbBots).filter((sb) => !cbIn.some((b) => String(b.id) === String(sb.id) && b._deleted));
      });
    }
  }
}

function isExpiredBot(b) {
  if (!b || !b.expiresAt) return false;
  return Number(b.expiresAt) < Date.now();
}

function applyAdminShared(doc, s) {
  const sh = doc.shared;
  if (typeof s.card === 'string') sh.card = s.card.slice(0, 64);
  if (isObj(s.promos)) {
    const p = {};
    Object.keys(s.promos).slice(0, 300).forEach((c) => {
      const v = Math.floor(Number(s.promos[c]));
      if (c.length <= 40 && v > 0 && v <= 1e9) p[c] = v;
    });
    sh.promos = p;
  }
  if (Array.isArray(s.tariffs)) {
    // validate & normalize every tariff admin pushes; only well-formed tariffs reach customers
    sh.tariffs = s.tariffs.filter(isObj).map((tf) => {
      const price = Math.floor(Number(tf.price));
      const days = Math.floor(Number(tf.days)) || 30;
      const cpu = Math.floor(Number(tf.cpu)) || 1;
      const mem = Math.floor(Number(tf.mem)) || 256;
      const storage = Math.floor(Number(tf.storage)) || 256;
      const name = String(tf.name || '').slice(0, 60);
      if (!name || price < 1 || price > 1e9) return null;
      return {
        id: String(tf.id || uidSrv()).slice(0, 40),
        name, price, days, cpu, mem, storage,
        active: tf.active === false ? false : true,
        createdAt: Number(tf.createdAt) || Date.now()
      };
    }).filter(Boolean).slice(0, 100);
  }
  if (Array.isArray(s.botTemplates)) {
    // CortenBots templates (cafe/shop/quiz/help ...): admin-managed, with a price per period.
    const oldMap = new Map((sh.botTemplates || []).map((t) => [t.id, t]));
    sh.botTemplates = s.botTemplates.filter(isObj).map((tf) => {
      const price = Math.floor(Number(tf.price));
      const days = Math.floor(Number(tf.days)) || 30;
      const name = String(tf.name || '').slice(0, 60);
      const icon = String(tf.icon || '🤖').slice(0, 8);
      const desc = String(tf.desc || '').slice(0, 160);
      if (!name || price < 0 || price > 1e9) return null;
      return {
        id: String(tf.id || uidSrv()).slice(0, 40),
        name, icon, desc, price, days,
        active: tf.active === false ? false : true,
        createdAt: Number(tf.createdAt) || Date.now()
      };
    }).filter(Boolean).slice(0, 100);
    // PRICE-CHANGE REFUND: when a template's price changes, every active (non-expired,
    // not-yet-refunded) cbBot of that template is refunded the pro-rated UNUSED portion
    // of what the customer actually paid: refund = paidPrice * remainingDays / totalDays.
    // The bot keeps running until its own expiresAt; new buyers pay the new price.
    const newMap = new Map((sh.botTemplates || []).map((t) => [t.id, t]));
    const now = Date.now();
    Object.values(doc.users).forEach((u) => {
      arr(u.cbBots).forEach((b) => {
        if (b.refunded) return;
        const oldT = oldMap.get(b.templateId);
        const newT = newMap.get(b.templateId);
        if (!oldT || !newT || Number(oldT.price) === Number(newT.price)) return;
        if (b.status === 'expired' || (b.expiresAt && Number(b.expiresAt) < now)) return;
        const totalDays = Number(b.days) || 30;
        const remaining = Math.max(0, Math.min(totalDays, Math.ceil((Number(b.expiresAt) - now) / 86400000)));
        const refund = Math.floor((Number(b.price) || 0) * remaining / totalDays);
        if (refund > 0) {
          u.balance = (u.balance || 0) + refund;
          doc.shared.earned = Math.max(0, (doc.shared.earned || 0) - refund);
          b.refunded = true;
          arr(u.transactions).unshift({ type: 'in', amount: refund, descKey: 'tx_cb_refund', params: { name: b.name, tariff: b.templateName }, time: now });
          arr(u.activity).unshift({ key: 'act_cb_refund', params: { amount: refund.toLocaleString('ru-RU'), name: b.name }, time: now });
        }
      });
    });
  }
  if (Array.isArray(s.notifs)) {
    const old = new Set(sh.notifs.map((n) => n.id));
    const fresh = s.notifs.filter((n) => isObj(n) && n.id && !old.has(n.id)).map((n) => n.id);
    sh.notifs = s.notifs.filter(isObj).slice(0, 200);
    if (fresh.length) { // new broadcast => everyone sees it as unread
      Object.values(doc.users).forEach((u) => { u.readNotifs = arr(u.readNotifs).filter((x) => !fresh.includes(x)); });
    }
  }
  if (Array.isArray(s.broadcasts)) sh.broadcasts = s.broadcasts.filter(isObj).slice(-200);
  if (Array.isArray(s.adminLogs)) sh.adminLogs = s.adminLogs.filter(isObj).slice(0, 100);
}

/* ---------- app ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(compression());
app.use(express.json({ limit: '30mb' }));

const hits = new Map();
function limiter(max) {
  return (req, res, next) => {
    const now = Date.now();
    const k = req.ip;
    let h = hits.get(k);
    if (!h || h.reset < now) h = { n: 0, reset: now + 10 * 60 * 1000 };
    h.n++; hits.set(k, h);
    if (h.n > max) return res.status(429).json({ error: 'toomany' });
    next();
  };
}
setInterval(() => { const n = Date.now(); hits.forEach((v, k) => { if (v.reset < n) hits.delete(k); }); }, 60000).unref();

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  if (e instanceof ApiError) return res.status(e.status).json({ error: e.code });
  console.error(e);
  res.status(500).json({ error: 'server' });
});
function tokenNick(req, required) {
  const h = req.headers.authorization || '';
  if (!h) { if (required) throw new ApiError(401, 'auth'); return null; }
  const nick = readToken(h.replace(/^Bearer\s+/i, ''));
  if (!nick) throw new ApiError(401, 'auth');
  return nick;
}
const needUser = (doc, nick) => { if (!has(doc.users, nick)) throw new ApiError(401, 'auth'); return doc.users[nick]; };

const NICK_RE = /^[\p{L}\p{N}_.\-]{3,32}$/u;
const BAD_NICKS = new Set(['__proto__', 'constructor', 'prototype', 'admin']);

app.get('/healthz', (req, res) => res.send('ok'));

app.post('/api/register', limiter(30), wrap(async (req, res) => {
  const nick = String((req.body || {}).nick || '').trim();
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const pass = String((req.body || {}).pass || '');
  if (!NICK_RE.test(nick)) throw new ApiError(400, 'badnick');
  if (!email.includes('@') || email.length > 120) throw new ApiError(400, 'bademail');
  if (pass.length < 6 || pass.length > 200) throw new ApiError(400, 'badpass');
  const out = await store.tx(async (doc) => {
    const lower = nick.toLowerCase();
    if (BAD_NICKS.has(lower) || Object.keys(doc.users).some((k) => k.toLowerCase() === lower)) throw new ApiError(409, 'nicktaken');
    if (Object.values(doc.users).some((u) => u.email === email)) throw new ApiError(409, 'emailtaken');
    doc.users[nick] = {
      nick, email, passHash: hashPw(pass), isAdmin: false, balance: 0,
      clientId: 10000000 + Math.floor(Math.random() * 89999999),
      bots: [], cbBots: [], trialUsed: false, messages: [], transactions: [],
      activity: [{ key: 'act_register', params: {}, time: Date.now() }],
      readNotifs: [], usedPromos: [], topupRequests: []
    };
    touch(doc);
    return reply(doc, nick, { token: signToken(nick) });
  });
  res.json(out);
}));

app.post('/api/login', limiter(40), wrap(async (req, res) => {
  const nick = String((req.body || {}).nick || '').trim();
  const pass = String((req.body || {}).pass || '');
  const doc = await store.read();
  const u = has(doc.users, nick) ? doc.users[nick] : null;
  if (!u || !verifyPw(pass, u.passHash)) throw new ApiError(401, 'wrong');
  res.json(reply(doc, nick, { token: signToken(nick) }));
}));

app.get('/api/sync', wrap(async (req, res) => {
  const nick = tokenNick(req, false);
  if (nick && Number(req.query.rev) === store.rev) {
    const d = await store.read();
    if (!has(d.users, nick)) throw new ApiError(401, 'auth');
    return res.json({ changed: false, rev: store.rev });
  }
  const doc = await store.read();
  if (nick) needUser(doc, nick);
  res.json(reply(doc, nick));
}));

app.put('/api/sync', wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const b = req.body || {};
  const out = await store.tx(async (doc) => {
    const me = needUser(doc, nick);
    if (me.isAdmin) {
      if (isObj(b.users)) {
        for (const k of Object.keys(b.users)) {
          if (has(doc.users, k)) mergeUser(doc.users[k], b.users[k], 'admin', doc);
        }
      }
      if (isObj(b.shared)) applyAdminShared(doc, b.shared);
      if (Array.isArray(b.readFiles)) {
        const ids = new Set(b.readFiles);
        doc.shared.fileUploads.forEach((f) => { if (ids.has(f.id)) f.read = true; });
      }
    } else {
      if (b.user) mergeUser(me, b.user, 'customer', doc);
      for (const f of arr(b.fileUploads).slice(0, 20)) {
        if (!isObj(f) || f.nick !== nick || typeof f.id !== 'string') continue;
        if (doc.shared.fileUploads.some((x) => x.id === f.id)) continue;
        const big = typeof f.dataUrl === 'string' && f.dataUrl.length > 1.6e6;
        doc.shared.fileUploads.unshift({
          id: f.id.slice(0, 40), nick, clientId: me.clientId,
          botId: f.botId, botName: String(f.botName || '').slice(0, 80),
          fileName: String(f.fileName || '').slice(0, 200), fileSize: Number(f.fileSize) || 0,
          mime: String(f.mime || '').slice(0, 100),
          dataUrl: (!big && typeof f.dataUrl === 'string') ? f.dataUrl : null, tooBig: !!f.tooBig || big,
          time: Number(f.time) || Date.now(), read: false
        });
        if (doc.shared.fileUploads.length > 200) doc.shared.fileUploads.length = 200;
      }
    }
    touch(doc);
    return reply(doc, nick);
  });
  res.json(out);
}));

app.post('/api/promo', limiter(60), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const code = String((req.body || {}).code || '').trim().toUpperCase();
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    if (u.isAdmin) throw new ApiError(400, 'invalid');
    const bonus = has(doc.shared.promos, code) ? doc.shared.promos[code] : 0;
    u.usedPromos = arr(u.usedPromos);
    if (!bonus || u.usedPromos.includes(code)) throw new ApiError(400, 'invalid');
    u.balance = (u.balance || 0) + bonus;
    u.usedPromos.push(code);
    const now = Date.now();
    u.transactions = arr(u.transactions); u.activity = arr(u.activity);
    u.transactions.unshift({ type: 'in', amount: bonus, descKey: 'tx_promo', params: {}, time: now });
    u.activity.unshift({ key: 'act_promo', params: { amount: Number(bonus).toLocaleString('ru-RU') }, time: now });
    touch(doc);
    return reply(doc, nick, { bonus });
  });
  res.json(out);
}));

// 1 TARIFF = 1 BOT — server-side bot creation with payment.
// A customer picks an active tariff; the server charges the balance and creates
// exactly ONE bot bound to that tariff. New bots can NEVER be added via /api/sync.
app.post('/api/create-bot', limiter(30), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const name = String((req.body || {}).name || '').trim();
  const tariffId = String((req.body || {}).tariffId || '');
  if (name.length < 2 || name.length > 80) throw new ApiError(400, 'badbotname');
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    if (u.isAdmin) throw new ApiError(400, 'invalid');
    const tf = (doc.shared.tariffs || []).find((x) => String(x.id) === tariffId && x.active !== false);
    if (!tf) throw new ApiError(400, 'badtariff');
    if ((arr(u.bots)).length >= 50) throw new ApiError(400, 'toomanybots');
    if ((u.balance || 0) < tf.price) throw new ApiError(400, 'insufficient');
    // charge the customer for this one tariff
    u.balance = (u.balance || 0) - tf.price;
    doc.shared.earned = (doc.shared.earned || 0) + tf.price;
    const now = Date.now();
    const days = Number(tf.days) || 30;
    const bot = {
      id: uidSrv(),
      name,
      status: 'off',
      mainFile: null,
      files: [],
      logs: [{ time: now, msg: 'Bot created. Tariff: ' + tf.name + ' · ' + tf.price.toLocaleString('ru-RU') + " so'm · " + days + ' days. 1 tariff = 1 bot.', kind: 'sys' }],
      createdAt: now,
      tariffId: tf.id,
      tariffName: tf.name,
      price: tf.price,
      days,
      expiresAt: now + days * 86400000
    };
    arr(u.bots).push(bot);
    u.transactions = arr(u.transactions);
    u.transactions.unshift({ type: 'out', amount: tf.price, descKey: 'tx_bot_create', params: { name, tariff: tf.name }, time: now });
    u.activity = arr(u.activity);
    u.activity.unshift({ key: 'act_bot_create', params: { name }, time: now });
    touch(doc);
    return reply(doc, nick, { botId: bot.id });
  });
  res.json(out);
}));

// A customer may delete its OWN bot by id (dedicated endpoint, not sync).
app.post('/api/delete-bot', limiter(30), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const botId = String((req.body || {}).id || '');
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    if (u.isAdmin) throw new ApiError(400, 'invalid');
    const before = arr(u.bots).length;
    u.bots = arr(u.bots).filter((b) => String(b.id) !== botId);
    if (u.bots.length === before) throw new ApiError(404, 'notfound');
    // also drop file uploads belonging to that bot
    doc.shared.fileUploads = arr(doc.shared.fileUploads).filter((f) => f.botId !== botId);
    u.activity = arr(u.activity);
    u.activity.unshift({ key: 'act_bot_stop', params: { name: botId }, time: Date.now() });
    touch(doc);
    return reply(doc, nick);
  });
  res.json(out);
}));

app.post('/api/delete-account', wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    if (u.isAdmin) throw new ApiError(400, 'invalid');
    delete doc.users[nick];
    touch(doc);
  });
  res.json({ ok: true });
}));

/* ---------- CortenBots: template-based bot creation (cafe / shop / quiz / help) ----------
   A CortenBots bot is created from an admin-priced template + a Telegram bot token.
   First bot per customer = 3-day free trial; later bots charge the template price.
   The customer can toggle their bot on/off. Actual Telegram polling is done by a
   best-effort Python sidecar (bot_runner.py, aiogram); if it is not installed the
   bot still exists with status on/off (status-only mode).                              */
const cbRunners = new Map(); // botId -> child process
async function tgGetMe(token){
  const r = await fetch('https://api.telegram.org/bot' + token + '/getMe');
  if (!r.ok) throw new Error('telegram');
  const j = await r.json();
  if (!j || !j.ok || !j.result || !j.result.username) throw new Error('nousername');
  return j.result.username;
}
function startCBRunner(token, templateId, botId){
  const runnerPath = path.join(__dirname, 'bot_runner.py');
  if (!fs.existsSync(runnerPath)) return; // runner not installed -> status-only mode
  try {
    const child = spawn('python3', ['-I', runnerPath, token, String(templateId), String(botId)], {
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true
    });
    cbRunners.set(String(botId), child);
    child.on('exit', () => cbRunners.delete(String(botId)));
  } catch (e) { /* ignore; status-only mode */ }
}
function stopCBRunner(botId){
  const child = cbRunners.get(String(botId));
  if (child) { try { child.kill('SIGTERM'); } catch (e) {} cbRunners.delete(String(botId)); }
}

app.post('/api/cb-create', limiter(20), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const name = String((req.body || {}).name || '').trim();
  const templateId = String((req.body || {}).templateId || '');
  const token = String((req.body || {}).token || '').trim();
  if (name.length < 2 || name.length > 80) throw new ApiError(400, 'badbotname');
  if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) throw new ApiError(400, 'badtoken');
  let tgUsername;
  try { tgUsername = await tgGetMe(token); }
  catch (e) { throw new ApiError(400, e.message === 'nousername' ? 'nousername' : 'badtoken'); }
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    if (u.isAdmin) throw new ApiError(400, 'invalid');
    u.cbBots = arr(u.cbBots);
    if (u.cbBots.length >= 20) throw new ApiError(400, 'toomanybots');
    if (u.cbBots.some((b) => b.token === token)) throw new ApiError(400, 'duptoken');
    const tf = (doc.shared.botTemplates || []).find((t) => String(t.id) === templateId && t.active !== false);
    if (!tf) throw new ApiError(400, 'badtemplate');
    const now = Date.now();
    const isTrial = !u.trialUsed;            // first bot = 3-day free trial
    const days = isTrial ? 3 : (Number(tf.days) || 30);
    const price = isTrial ? 0 : tf.price;
    if (!isTrial && (u.balance || 0) < price) throw new ApiError(400, 'insufficient');
    if (!isTrial) {
      u.balance = (u.balance || 0) - price;
      doc.shared.earned = (doc.shared.earned || 0) + price;
    }
    u.trialUsed = true;
    const bot = {
      id: uidSrv(), name, templateId: tf.id, templateName: tf.name, templateIcon: tf.icon,
      token, tgUsername, status: 'on', isTrial, refunded: false, days, price,
      createdAt: now, expiresAt: now + days * 86400000,
      logs: [{ time: now, msg: (isTrial ? 'Bot yaratildi — 3 kun bepul sinov. ' : 'Bot yaratildi. Tarif: ' + tf.name + ' · ' + price.toLocaleString('ru-RU') + " so'm · " + days + ' kun. ') + 'Telegramda /start yuboring.', kind: 'sys' }]
    };
    u.cbBots.push(bot);
    u.transactions = arr(u.transactions);
    if (!isTrial) u.transactions.unshift({ type: 'out', amount: price, descKey: 'tx_cb_create', params: { name, tariff: tf.name }, time: now });
    u.activity = arr(u.activity);
    u.activity.unshift({ key: 'act_cb_create', params: { name }, time: now });
    touch(doc);
    return reply(doc, nick, { botId: bot.id, cbToken: token, cbTpl: tf.id });
  });
  startCBRunner(out.cbToken, out.cbTpl, out.botId);
  delete out.cbToken; delete out.cbTpl;
  res.json(out);
}));

app.post('/api/cb-toggle', limiter(40), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const botId = String((req.body || {}).botId || '');
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    const b = arr(u.cbBots).find((x) => String(x.id) === botId);
    if (!b) throw new ApiError(404, 'notfound');
    if (b.status === 'expired' || (b.expiresAt && Number(b.expiresAt) < Date.now())) {
      b.status = 'expired'; throw new ApiError(400, 'expired');
    }
    b.status = b.status === 'on' ? 'off' : 'on';
    arr(b.logs).unshift({ time: Date.now(), msg: b.status === 'on' ? 'Bot yoqildi.' : "Bot o'chirildi.", kind: 'sys' });
    b.logs = arr(b.logs).slice(-120);
    touch(doc);
    return reply(doc, nick, { cbStatus: b.status, cbToken: b.token, cbTpl: b.templateId });
  });
  if (out.cbStatus === 'on') startCBRunner(out.cbToken, out.cbTpl, botId);
  else stopCBRunner(botId);
  delete out.cbToken; delete out.cbTpl;
  res.json(out);
}));

app.post('/api/cb-delete', limiter(30), wrap(async (req, res) => {
  const nick = tokenNick(req, true);
  const botId = String((req.body || {}).botId || '');
  const out = await store.tx(async (doc) => {
    const u = needUser(doc, nick);
    const before = arr(u.cbBots).length;
    u.cbBots = arr(u.cbBots).filter((b) => String(b.id) !== botId);
    if (u.cbBots.length === before) throw new ApiError(404, 'notfound');
    u.activity = arr(u.activity);
    u.activity.unshift({ key: 'act_cb_delete', params: { name: botId }, time: Date.now() });
    touch(doc);
    return reply(doc, nick);
  });
  stopCBRunner(botId);
  res.json(out);
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'notfound' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'toolarge' });
  console.error(err);
  res.status(400).json({ error: 'bad' });
});

/* ---------- start ---------- */
(async () => {
  await store.init();
  // make sure the admin account exists and uses ADMIN_PASSWORD
  await store.tx(async (doc) => {
    const a = doc.users.admin;
    if (!a) {
      doc.users.admin = {
        nick: 'admin', email: 'admin@cortencloud.uz', passHash: hashPw(ADMIN_PASSWORD), isAdmin: true,
        balance: 0, clientId: 10000001, bots: [], cbBots: [], trialUsed: true, messages: [], transactions: [],
        activity: [], readNotifs: [], usedPromos: [], topupRequests: []
      };
      touch(doc);
    } else if (!verifyPw(ADMIN_PASSWORD, a.passHash)) {
      a.passHash = hashPw(ADMIN_PASSWORD);
      touch(doc);
    }
    // seed default CortenBots templates (cafe/shop/quiz/help) on first run
    if (!arr(doc.shared.botTemplates).length) {
      doc.shared.botTemplates = [
        { id: 'cafe', name: 'Kafe boti', icon: '☕', desc: 'Menyu, buyurtma va yetkazib berish', price: 39000, days: 30, active: true, createdAt: Date.now() },
        { id: 'shop', name: "Do'kon boti", icon: '🛍️', desc: 'Katalog, savat va buyurtma qabul qilish', price: 49000, days: 30, active: true, createdAt: Date.now() },
        { id: 'quiz', name: 'Quiz boti', icon: '🧠', desc: 'Test, ball va natijalar', price: 29000, days: 30, active: true, createdAt: Date.now() },
        { id: 'help', name: 'Yordam boti', icon: '💬', desc: 'Ticket tizimi va FAQ', price: 24000, days: 30, active: true, createdAt: Date.now() }
      ];
      touch(doc);
    }
  });
  app.listen(PORT, () => console.log('CortenCloud running on :' + PORT));
})().catch((e) => { console.error(e); process.exit(1); });
