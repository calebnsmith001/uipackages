const express = require('express');
const fs = require('fs');

const app = express();
// Key: trust the Render reverse proxy so req.ip resolves the real client IP from X-Forwarded-For
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';      // Protects /logs* pages (set this in production)
const COLLECT_TOKEN = process.env.COLLECT_TOKEN || '';  // Protects the /collect reporting endpoint (optional)
const MAX_MEMORY_LOGS = parseInt(process.env.MAX_MEMORY_LOGS || '2000', 10);
const LOG_FILE = process.env.LOG_FILE || '';            // Optional: also write to a local file (lost on restart)

const logs = []; // In-memory ring buffer

function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
const csvCell = v => `"${String(v ?? '').replace(/"/g, '""')}"`;

function pushLog(rec) {
  logs.push(rec);
  if (logs.length > MAX_MEMORY_LOGS) logs.shift();
  // stdout: Render collects this automatically, viewable in Dashboard -> Logs
  console.log(JSON.stringify(rec));
  if (LOG_FILE) fs.appendFile(LOG_FILE, JSON.stringify(rec) + '\n', () => {});
}

// ---------- Access log middleware: record time + IP ----------
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const xff = String(req.headers['x-forwarded-for'] || '');
    pushLog({
      time: new Date().toISOString(),          // UTC time
      ip: xff.split(',')[0].trim() || req.ip,  // Real client IP
      forwarded_chain: xff || undefined,       // Full proxy chain (for troubleshooting)
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      duration_ms: Date.now() - start,
      user_agent: req.headers['user-agent'] || ''
    });
  });
  next();
});

app.use(express.json({ limit: '64kb' }));

// ---------- Auth ----------
function auth(req, res, next) {
  if (!ADMIN_TOKEN) return next(); // No protection if token is unset (testing only)
  const key = req.query.key || req.get('x-admin-token');
  if (key === ADMIN_TOKEN) return next();
  res.status(401).type('text/plain').send('Unauthorized');
}

// ---------- Home / health check ----------
app.get('/', (req, res) => {
  res.type('text/plain').send(
    'Access log collector is running.\n' +
    'GET /logs?key=TOKEN       View log page\n' +
    'GET /logs.csv?key=TOKEN   Export CSV\n' +
    'GET /logs.json?key=TOKEN  Export JSON\n' +
    'POST /collect             Submit external logs\n'
  );
});

// ---------- Log viewer page (auto-refresh every 10s) ----------
app.get('/logs', auth, (req, res) => {
  const rows = logs.slice().reverse().map(r => `<tr>
    <td>${esc(r.time)}</td><td><b>${esc(r.ip)}</b></td>
    <td>${esc(r.method)}</td><td>${esc(r.path)}</td>
    <td>${esc(r.status)}</td><td>${esc(r.duration_ms)}</td>
    <td>${esc(r.user_agent)}</td></tr>`).join('');
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
  <title>Access Logs (${logs.length})</title>
  <meta http-equiv="refresh" content="10">
  <style>body{font-family:monospace;background:#111;color:#ddd;padding:16px}
  table{border-collapse:collapse;width:100%}td,th{border:1px solid #444;padding:4px 8px;font-size:13px}
  th{background:#222}tr:hover{background:#1c2b3a}</style></head><body>
  <h2>Recent Access Logs (total: ${logs.length}, auto-refresh: 10s)</h2>
  <p><a href="/logs.csv?key=${esc(req.query.key || '')}" style="color:#7ab">Export CSV</a> |
     <a href="/logs.json?key=${esc(req.query.key || '')}" style="color:#7ab">Export JSON</a></p>
  <table><tr><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>ms</th><th>User-Agent</th></tr>
  ${rows}</table></body></html>`);
});

// ---------- CSV / JSON export ----------
app.get('/logs.csv', auth, (req, res) => {
  const head = 'time,ip,method,path,status,duration_ms,user_agent';
  const body = logs.map(r => [r.time, r.ip, r.method, r.path, r.status, r.duration_ms, r.user_agent].map(csvCell).join(','));
  res.attachment('access-logs.csv').send([head, ...body].join('\n'));
});

app.get('/logs.json', auth, (req, res) => {
  res.attachment('access-logs.json').json(logs);
});

// ---------- External log submission endpoint (collector mode) ----------
app.post('/collect', (req, res) => {
  if (COLLECT_TOKEN) {
    const t = req.get('x-collect-token') || req.query.key;
    if (t !== COLLECT_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  }
  const b = req.body || {};
  const xff = String(req.headers['x-forwarded-for'] || '');
  pushLog({
    time: b.time || new Date().toISOString(),
    ip: b.ip || xff.split(',')[0].trim() || req.ip,
    source: b.source || 'collect',
    method: b.method || '-',
    path: b.path || '-',
    user_agent: b.user_agent || req.headers['user-agent'] || '',
    extra: b
  });
  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Listening on port ${PORT}`));