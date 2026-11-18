'use strict';
const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const jsQR = require('jsqr');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { analyzeContent } = require('./analyzer');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ───────────── tiny JSON-file store (atomic writes) ───────────── */
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJSON(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}
let scans = readJSON(SCANS_FILE, []);
let settings = readJSON(SETTINGS_FILE, { sensitivity: 'medium' });

/* ───────────── QR decoding from image buffers ───────────── */
async function decodeQR(buffer) {
  const base = sharp(buffer, { failOn: 'none' }).rotate(); // honour EXIF orientation
  const meta = await base.metadata();
  const maxSide = Math.max(meta.width || 0, meta.height || 0);
  // Try several scales: tiny codes need upscaling, huge photos need shrinking.
  const sizes = [...new Set([Math.min(maxSide, 1000), 600, 1600, 400, 300].filter((s) => s > 0))];
  for (const size of sizes) {
    for (const variant of ['plain', 'sharpen', 'threshold']) {
      let pipe = base.clone().resize({ width: size, height: size, fit: 'inside', withoutEnlargement: false })
        .flatten({ background: '#ffffff' }).ensureAlpha();
      if (variant === 'sharpen') pipe = pipe.sharpen();
      if (variant === 'threshold') pipe = pipe.greyscale().normalise().threshold(128).toColourspace('srgb').ensureAlpha();
      const { data, info } = await pipe.raw().toBuffer({ resolveWithObject: true });
      let code = null;
      try {
        code = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.length), info.width, info.height, {
          inversionAttempts: 'attemptBoth',
        });
      } catch { /* jsQR throws on blank/uniform images: treat as "no code" */ }
      if (code && code.data) return code.data;
    }
  }
  return null;
}

/* ───────────── helpers ───────────── */
function saveScan(content, source, analysis, extra = {}) {
  const record = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    content,
    source, // 'camera' | 'upload' | 'url-checker'
    verdict: analysis.verdict,
    score: analysis.score,
    type: analysis.type,
    findings: analysis.findings,
    summary: analysis.summary,
    sensitivity: analysis.sensitivity,
    ...extra,
  };
  scans.unshift(record);
  if (scans.length > 5000) scans.length = 5000;
  writeJSON(SCANS_FILE, scans);
  return record;
}

function computeStats() {
  const total = scans.length;
  const count = (v) => scans.filter((s) => s.verdict === v).length;
  const safe = count('safe'), suspicious = count('suspicious'), malicious = count('malicious');

  // last 7 days activity
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    days.push(d);
  }
  const activity = days.map((d) => {
    const next = new Date(d); next.setDate(next.getDate() + 1);
    const inDay = scans.filter((s) => { const t = new Date(s.timestamp); return t >= d && t < next; });
    return {
      date: d.toISOString().slice(0, 10),
      label: d.toLocaleDateString('en-US', { weekday: 'short' }),
      safe: inDay.filter((s) => s.verdict === 'safe').length,
      suspicious: inDay.filter((s) => s.verdict === 'suspicious').length,
      malicious: inDay.filter((s) => s.verdict === 'malicious').length,
    };
  });

  // threat level from recent 20 scans
  const recent = scans.slice(0, 20);
  const risk = recent.length
    ? Math.round(recent.reduce((a, s) => a + (s.verdict === 'malicious' ? 100 : s.verdict === 'suspicious' ? 50 : 0), 0) / recent.length)
    : 0;
  const level = risk >= 60 ? 'HIGH' : risk >= 25 ? 'MEDIUM' : 'LOW';

  const bySource = {};
  scans.forEach((s) => { bySource[s.source] = (bySource[s.source] || 0) + 1; });

  return { total, safe, suspicious, malicious, activity, threatLevel: { level, percent: risk }, bySource };
}

/* ───────────── reports ───────────── */
function buildTextReport() {
  const st = computeStats();
  const line = '='.repeat(64);
  const out = [
    line, '  QR SHIELD — SCAN SUMMARY REPORT', line,
    `Generated : ${new Date().toLocaleString()}`,
    `Sensitivity: ${settings.sensitivity}`,
    '',
    'SUMMARY', '-'.repeat(64),
    `Total scans : ${st.total}`,
    `Safe        : ${st.safe}`,
    `Suspicious  : ${st.suspicious}`,
    `Malicious   : ${st.malicious}`,
    `Threat level: ${st.threatLevel.level} (${st.threatLevel.percent}%)`,
    '',
    'THREATS (suspicious + malicious)', '-'.repeat(64),
  ];
  const threats = scans.filter((s) => s.verdict !== 'safe');
  if (!threats.length) out.push('None detected.');
  threats.forEach((s, i) => {
    out.push(`${i + 1}. [${s.verdict.toUpperCase()}] score ${s.score}/100 — ${new Date(s.timestamp).toLocaleString()} (${s.source})`);
    out.push(`   ${s.content}`);
    s.findings.filter((f) => f.level !== 'good').forEach((f) => out.push(`   • ${f.title}: ${f.detail}`));
    out.push('');
  });
  out.push('FULL HISTORY', '-'.repeat(64));
  if (!scans.length) out.push('No scans recorded.');
  scans.forEach((s, i) => {
    out.push(`${String(i + 1).padStart(3)}. ${new Date(s.timestamp).toLocaleString()} | ${s.verdict.toUpperCase().padEnd(10)} | ${s.source.padEnd(11)} | ${s.content}`);
  });
  out.push('', line, 'End of report', line);
  return out.join('\n');
}

function csvEscape(v) { return '"' + String(v ?? '').replace(/"/g, '""') + '"'; }
function buildCsv() {
  const rows = [['id', 'timestamp', 'source', 'type', 'verdict', 'score', 'content', 'findings']];
  scans.forEach((s) => rows.push([s.id, s.timestamp, s.source, s.type, s.verdict, s.score, s.content,
    s.findings.filter((f) => f.level !== 'good').map((f) => f.title).join('; ')]));
  return '\uFEFF' + rows.map((r) => r.map(csvEscape).join(',')).join('\r\n');
}

/* ───────────── app ───────────── */
const app = express();
// Allow the page to be opened from disk (file:// → Origin "null") or from localhost only.
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o === 'null' || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o || '')) {
    res.set({ 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => cb(/^image\//.test(file.mimetype) ? null : new Error('Only image files are allowed'), /^image\//.test(file.mimetype)),
});

const validContent = (s) => typeof s === 'string' && s.trim().length > 0 && s.length <= 4096;

// Scan from camera (browser decodes, backend analyses & stores)
app.post('/api/analyze', (req, res) => {
  const { content, source } = req.body || {};
  if (!validContent(content)) return res.status(400).json({ error: 'Provide QR "content" (1–4096 chars).' });
  const analysis = analyzeContent(content, { sensitivity: settings.sensitivity });
  const record = saveScan(content.trim(), source === 'upload' ? 'upload' : 'camera', analysis);
  res.json({ scan: record });
});

// Upload an image; backend decodes the QR and analyses it
app.post('/api/upload', upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image uploaded (field name: "image").' });
  try {
    const content = await decodeQR(req.file.buffer);
    if (!content) return res.status(422).json({ error: 'No QR code could be found in this image. Try a clearer, closer picture.' });
    const analysis = analyzeContent(content, { sensitivity: settings.sensitivity });
    const record = saveScan(content, 'upload', analysis, { fileName: req.file.originalname });
    res.json({ scan: record });
  } catch (e) {
    console.error('Upload decode error:', e.message);
    res.status(422).json({ error: 'Could not read that image file.' });
  }
});

// URL checker
app.post('/api/url', (req, res) => {
  const { url } = req.body || {};
  if (!validContent(url)) return res.status(400).json({ error: 'Provide a "url" (1–4096 chars).' });
  const analysis = analyzeContent(url.trim(), { sensitivity: settings.sensitivity });
  const record = saveScan(url.trim(), 'url-checker', analysis);
  res.json({ scan: record });
});

app.get('/api/history', (req, res) => {
  const { verdict } = req.query;
  res.json({ scans: verdict ? scans.filter((s) => s.verdict === verdict) : scans });
});
app.delete('/api/history/:id', (req, res) => {
  const before = scans.length;
  scans = scans.filter((s) => s.id !== req.params.id);
  if (scans.length === before) return res.status(404).json({ error: 'Not found' });
  writeJSON(SCANS_FILE, scans);
  res.json({ ok: true });
});
app.delete('/api/history', (req, res) => {
  scans = [];
  writeJSON(SCANS_FILE, scans);
  res.json({ ok: true });
});

app.get('/api/stats', (req, res) => res.json(computeStats()));
app.get('/api/alerts', (req, res) => res.json({ alerts: scans.filter((s) => s.verdict !== 'safe') }));

app.get('/api/settings', (req, res) => res.json(settings));
app.put('/api/settings', (req, res) => {
  const { sensitivity } = req.body || {};
  if (!['low', 'medium', 'high'].includes(sensitivity)) return res.status(400).json({ error: 'sensitivity must be low, medium or high' });
  settings = { ...settings, sensitivity };
  writeJSON(SETTINGS_FILE, settings);
  res.json(settings);
});

app.get('/api/report', (req, res) => {
  const stamp = new Date().toISOString().slice(0, 10);
  const format = (req.query.format || 'txt').toLowerCase();
  if (format === 'csv') {
    res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="qr-shield-report-${stamp}.csv"` });
    return res.send(buildCsv());
  }
  if (format === 'json') {
    res.set({ 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="qr-shield-report-${stamp}.json"` });
    return res.send(JSON.stringify({ generated: new Date().toISOString(), stats: computeStats(), scans }, null, 2));
  }
  res.set({ 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': `attachment; filename="qr-shield-report-${stamp}.txt"` });
  res.send(buildTextReport());
});
app.get('/api/report/preview', (req, res) => res.json({ stats: computeStats(), settings, recent: scans.slice(0, 10) }));

// error handler (multer errors etc.)
app.use((err, req, res, next) => {
  const code = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
  res.status(code).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Image too large (max 8 MB).' : err.message });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`QR Shield running at http://localhost:${PORT}`));
}
module.exports = { app, decodeQR };
