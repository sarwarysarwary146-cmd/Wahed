const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PORT = process.env.PORT || 3000;

let db = { users: {}, tokens: {}, msgs: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) {}
let timer = null;
const save = () => {
  clearTimeout(timer);
  timer = setTimeout(() => fs.writeFile(FILE, JSON.stringify(db), () => {}), 300);
};

const key = n => n.toLowerCase();
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Simple brute-force guard: 30 attempts per 10 minutes per IP
const tries = new Map();
function limited(ip) {
  const now = Date.now();
  const a = (tries.get(ip) || []).filter(t => now - t < 600000);
  a.push(now);
  tries.set(ip, a);
  return a.length > 30;
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2kb' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

function auth(kind) {
  return (req, res) => {
    if (limited(req.ip)) return res.json({ error: 'تلاش زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید' });
    const name = String((req.body && req.body.name) || '').trim();
    const pw = String((req.body && req.body.password) || '');
    let user;
    if (kind === 'signup') {
      if (!/^[\p{L}\p{N}_ .-]{2,20}$/u.test(name)) return res.json({ error: 'نام باید بین ۲ تا ۲۰ حرف باشد' });
      if (pw.length < 4 || pw.length > 100) return res.json({ error: 'رمز باید حداقل ۴ کاراکتر باشد' });
      if (db.users[key(name)]) return res.json({ error: 'این نام قبلاً گرفته شده است' });
      const salt = crypto.randomBytes(16).toString('hex');
      user = db.users[key(name)] = { name, salt, hash: hash(pw, salt) };
    } else {
      user = db.users[key(name)];
      if (!user || !same(hash(pw, user.salt), user.hash)) return res.json({ error: 'نام یا رمز اشتباه است' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    db.tokens[token] = key(user.name);
    save();
    res.json({ token, name: user.name });
  };
}
app.post('/api/signup', auth('signup'));
app.post('/api/login', auth('login'));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 4096 });
const online = new Map(); // user key -> Set of sockets

const userList = () => Object.values(db.users).map(u => ({ name: u.name, online: online.has(key(u.name)) }));
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const all = o => wss.clients.forEach(c => c.k && send(c, o));

wss.on('connection', (ws, req) => {
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  const k = db.tokens[token];
  if (!k || !db.users[k]) return ws.close(4401);
  ws.k = k;
  ws.alive = true;
  if (!online.has(k)) online.set(k, new Set());
  online.get(k).add(ws);
  const me = db.users[k].name;

  const mine = db.msgs.filter(m => m.to === '*' || m.fk === k || m.tk === k).slice(-600)
    .map(m => ({ id: m.id, from: m.from, to: m.to, text: m.text, ts: m.ts }));
  send(ws, { type: 'init', me, users: userList(), msgs: mine });
  all({ type: 'users', users: userList() });

  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', raw => {
    let d;
    try { d = JSON.parse(raw); } catch (e) { return; }
    if (!d || d.type !== 'msg') return;
    const text = String(d.text || '').trim().slice(0, 1000);
    if (!text) return;
    let to = null;
    if (d.to === '*') to = '*';
    else if (db.users[key(String(d.to))]) to = db.users[key(String(d.to))].name;
    if (!to) return;
    const m = { id: crypto.randomUUID(), from: me, fk: k, to, tk: to === '*' ? '*' : key(to), text, ts: Date.now() };
    db.msgs.push(m);
    if (db.msgs.length > 5000) db.msgs.splice(0, db.msgs.length - 5000);
    save();
    const out = { type: 'msg', msg: { id: m.id, from: m.from, to: m.to, text: m.text, ts: m.ts } };
    if (to === '*') all(out);
    else new Set([...(online.get(k) || []), ...(online.get(m.tk) || [])]).forEach(c => send(c, out));
  });
  ws.on('close', () => {
    const s = online.get(k);
    if (s) { s.delete(ws); if (!s.size) online.delete(k); }
    all({ type: 'users', users: userList() });
  });
});

// Keep connections alive behind hosting proxies
setInterval(() => {
  wss.clients.forEach(c => {
    if (c.alive === false) return c.terminate();
    c.alive = false;
    c.ping();
  });
}, 30000);

server.listen(PORT, () => console.log('Chat running on port ' + PORT));
