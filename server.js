const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const Database = require('better-sqlite3');
const SCHEMA = require('./schema');

// ---- storage locations (Railway volume mounts at DATA_DIR) ----
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';

// ---- database ----
const db = new Database(path.join(DATA_DIR, 'onboarding.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  answers TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  submitted_at TEXT
);
CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY,
  client_id INTEGER NOT NULL,
  field_key TEXT,
  orig_name TEXT NOT NULL,
  stored_name TEXT NOT NULL,
  size INTEGER,
  created_at TEXT NOT NULL
);
`);

// migrations (safe to run repeatedly)
{
  const cols = db.prepare("PRAGMA table_info(clients)").all().map(c => c.name);
  if (!cols.includes('analysis')) db.exec("ALTER TABLE clients ADD COLUMN analysis TEXT");
  if (!cols.includes('analyzed_at')) db.exec("ALTER TABLE clients ADD COLUMN analyzed_at TEXT");
}

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5';

const now = () => new Date().toISOString();
const byToken = db.prepare('SELECT * FROM clients WHERE token = ?');

const app = express();
app.use(express.json({ limit: '3mb' }));

// ---- shared schema for the browser (form + admin) ----
app.get('/schema.js', (req, res) =>
  res.type('application/javascript').send('window.PSA_SCHEMA=' + JSON.stringify(SCHEMA)));

// ================= CLIENT FORM =================
app.get('/f/:token', (req, res) => {
  if (!byToken.get(req.params.token)) return res.status(404).send('Посилання недійсне або застаріле.');
  res.sendFile(path.join(__dirname, 'public', 'form.html'));
});

app.get('/api/form/:token', (req, res) => {
  const c = byToken.get(req.params.token);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const files = db.prepare('SELECT id, field_key, orig_name FROM files WHERE client_id=?').all(c.id);
  res.json({ name: c.name, status: c.status, answers: JSON.parse(c.answers || '{}'), files });
});

app.post('/api/form/:token/save', (req, res) => {
  const c = byToken.get(req.params.token);
  if (!c) return res.status(404).json({ error: 'not_found' });
  db.prepare("UPDATE clients SET answers=?, status=CASE WHEN status='new' THEN 'in_progress' ELSE status END WHERE id=?")
    .run(JSON.stringify(req.body.answers || {}), c.id);
  res.json({ ok: true });
});

app.post('/api/form/:token/submit', (req, res) => {
  const c = byToken.get(req.params.token);
  if (!c) return res.status(404).json({ error: 'not_found' });
  db.prepare("UPDATE clients SET answers=?, status='submitted', submitted_at=? WHERE id=?")
    .run(JSON.stringify(req.body.answers || {}), now(), c.id);
  res.json({ ok: true });
});

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname))
  }),
  limits: { fileSize: 50 * 1024 * 1024 }
});
app.post('/api/form/:token/upload', upload.single('file'), (req, res) => {
  const c = byToken.get(req.params.token);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const id = crypto.randomUUID();
  const orig = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
  db.prepare('INSERT INTO files(id,client_id,field_key,orig_name,stored_name,size,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(id, c.id, req.body.field_key || null, orig, req.file.filename, req.file.size, now());
  res.json({ id, name: orig });
});

// ================= ADMIN =================
function adminAuth(req, res, next) {
  const [type, val] = (req.headers.authorization || '').split(' ');
  if (type === 'Basic') {
    const [, p] = Buffer.from(val || '', 'base64').toString().split(':');
    if (p === ADMIN_PASSWORD) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="ProSales Admin"').status(401).send('Потрібна авторизація');
}

app.get('/admin', adminAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.get('/api/admin/clients', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT id,token,name,status,created_at,submitted_at FROM clients ORDER BY id DESC').all());
});

app.post('/api/admin/clients', adminAuth, (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name_required' });
  const token = crypto.randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO clients(token,name,created_at) VALUES(?,?,?)').run(token, name, now());
  res.json({ token });
});

app.get('/api/admin/clients/:id', adminAuth, (req, res) => {
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const files = db.prepare('SELECT id, field_key, orig_name FROM files WHERE client_id=?').all(c.id);
  res.json({ ...c, answers: JSON.parse(c.answers || '{}'), files });
});

app.delete('/api/admin/clients/:id', adminAuth, (req, res) => {
  const files = db.prepare('SELECT stored_name FROM files WHERE client_id=?').all(req.params.id);
  files.forEach(f => { try { fs.unlinkSync(path.join(UPLOAD_DIR, f.stored_name)); } catch (e) {} });
  db.prepare('DELETE FROM files WHERE client_id=?').run(req.params.id);
  db.prepare('DELETE FROM clients WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/files/:id', adminAuth, (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).send('Файл не знайдено');
  res.download(path.join(UPLOAD_DIR, f.stored_name), f.orig_name);
});

// ---- format a filled brief into plain text (empties shown as gaps) ----
function valText(f, v) {
  const empty = v == null || v === '' || (Array.isArray(v) && v.length === 0);
  if (empty) return '∅ (не заповнено)';
  const t = f.t;
  if (t === 'text' || t === 'ta' || t === 'tabig') return String(v);
  if (t === 'row2' || t === 'row3') return v.filter(Boolean).join(', ') || '∅';
  if (t === 'check') return v.map(i => f.o[i]).join(', ');
  if (t === 'radiox') { let s = v.sel >= 0 ? f.o[v.sel] : ''; if (v.extra) s += (s ? ' — ' : '') + v.extra; return s || '∅'; }
  if (t === 'drop' || t === 'dropbig') return v.map(x => x.name).join('; ') + ` (файлів: ${v.length})`;
  if (t === 'tbl' || t === 'cards') {
    const rows = v.filter(r => r.some(c => c && c.trim()));
    if (!rows.length) return '∅';
    return rows.map((r, i) => `\n    ${i + 1}) ` + f.cols.map((c, ci) => `${c}: ${r[ci] || '—'}`).join(' | ')).join('');
  }
  if (t === 'journey') return v.map((r, ri) => `\n    ${f.stages[ri]}: що=${r[0] || '—'}, хто=${r[1] || '—'}, канал=${r[2] || '—'}, далі=${r[3] || '—'}`).join('');
  if (t === 'cal') return f.items.map((it, i) => v[i] ? `${it}: ${v[i]}` : null).filter(Boolean).join('; ') || '∅';
  return String(v);
}
function formatBrief(answers) {
  let out = '';
  SCHEMA.forEach((s, si) => {
    out += `\n## ${si + 1}. ${s.n}\n`;
    s.f.forEach((f, fi) => { out += `- ${f.l || f.t}: ${valText(f, answers['s' + si + '_f' + fi])}\n`; });
  });
  return out;
}

const AI_SYSTEM = `Ти — досвідчений керівник відділу продажів (РОП) в агенції, яка продає онлайн-курси та освітні продукти інфобізнесу. Тобі дають заповнений онбординг-бриф по продукту клієнта. Завдання — підготувати продуктовий дзвінок: знайти, чого бракує у брифі або що розкрито поверхово чи неоднозначно, і сформулювати конкретні питання, які РОП/менеджер має поставити клієнту, щоб закрити ці прогалини перед стартом продажів.

Правила:
- Не переказуй те, що вже добре розкрито. Фокус — на прогалинах, суперечностях і слабких місцях.
- Поля з позначкою «∅ (не заповнено)» — це прямі прогалини; критичні винеси в пріоритет.
- Питання мають бути конкретні й готові до озвучення, а не загальні («розкажіть більше»).
- Особлива увага: оффер і трансформація, аудиторія (болі, заперечення, точка А/Б), тарифи й ціноутворення, декомпозиція запуску та історичні цифри, воронки, кейси, конкуренти.
- Пиши стисло й по суті. Відповідай українською у форматі Markdown.`;

app.post('/api/admin/clients/:id/analyze', adminAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(400).json({ error: 'no_key', message: 'Не задано ANTHROPIC_API_KEY у змінних середовища Railway.' });
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  const brief = formatBrief(JSON.parse(c.answers || '{}'));
  const user = `Ось заповнений бриф клієнта «${c.name}»:\n${brief}\n\nСклади:\n1. **Топ-питання для дзвінка** — 8–12 найважливіших питань за пріоритетом.\n2. **Прогалини по розділах** — де тонко, з конкретними питаннями.\n3. **Червоні прапорці** — що завадить продажам, якщо не уточнити.`;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: ANTHROPIC_MODEL, max_tokens: 2200, system: AI_SYSTEM, messages: [{ role: 'user', content: user }] })
    });
    const d = await r.json();
    if (!r.ok) return res.status(502).json({ error: 'api', message: (d.error && d.error.message) || 'Помилка API' });
    const text = (d.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    const at = now();
    db.prepare('UPDATE clients SET analysis=?, analyzed_at=? WHERE id=?').run(text, at, c.id);
    res.json({ analysis: text, analyzed_at: at });
  } catch (e) {
    res.status(502).json({ error: 'network', message: String(e) });
  }
});

// ---- exports ----
app.get('/api/admin/export.json', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT id,name,status,created_at,submitted_at,answers,analysis FROM clients ORDER BY id').all()
    .map(c => ({ ...c, answers: JSON.parse(c.answers || '{}') }));
  res.setHeader('Content-Disposition', 'attachment; filename="prosales-export.json"');
  res.json(rows);
});
app.get('/api/admin/clients/:id/dossier.md', adminAuth, (req, res) => {
  const c = db.prepare('SELECT * FROM clients WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).send('not found');
  let md = `# Досьє продукту — ${c.name}\n`;
  md += formatBrief(JSON.parse(c.answers || '{}'));
  if (c.analysis) md += `\n\n---\n\n# Питання для продуктового дзвінка (AI)\n\n${c.analysis}\n`;
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="dossier-${c.id}.md"`);
  res.send(md);
});

app.get('/', (req, res) => res.redirect('/admin'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('ProSales onboarding running on :' + PORT));
