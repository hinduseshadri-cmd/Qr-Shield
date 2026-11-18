'use strict';
// End-to-end test: generates QR images, starts the server, hits every endpoint.
const os = require('os');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const QRCode = require('qrcode');
const sharp = require('sharp');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'qrshield-'));
const { app } = require('../server');

async function qrPng(text, opts = {}) {
  return QRCode.toBuffer(text, { width: 300, margin: 4, ...opts });
}
async function upload(base, buf, name = 'qr.png', type = 'image/png') {
  const fd = new FormData();
  fd.append('image', new Blob([buf], { type }), name);
  return fetch(base + '/api/upload', { method: 'POST', body: fd });
}

(async () => {
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const j = (p, o) => fetch(base + p, o).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null), res: r }));
  const post = (p, data) => j(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
  let n = 0; const ok = (msg) => console.log(`  ✓ ${++n}. ${msg}`);

  // --- /api/url verdicts
  let r = await post('/api/url', { url: 'https://www.google.com/search?q=cats' });
  assert.equal(r.body.scan.verdict, 'safe'); ok('clean HTTPS URL → safe');
  r = await post('/api/url', { url: 'http://192.168.4.5/login/verify' });
  assert.equal(r.body.scan.verdict, 'malicious'); ok('http + IP + keywords → malicious');
  r = await post('/api/url', { url: 'https://my-shop.example.tk/home' });
  assert.equal(r.body.scan.verdict, 'suspicious'); ok('suspicious TLD alone → suspicious (score ' + r.body.scan.score + ')');
  r = await post('/api/url', { url: 'https://free-prize.example.tk/claim' });
  assert.equal(r.body.scan.verdict, 'malicious'); ok('suspicious TLD + prize keywords → malicious (score ' + r.body.scan.score + ')');
  r = await post('/api/url', { url: 'http://paypal-secure-login.xyz/update.apk' });
  assert.equal(r.body.scan.verdict, 'malicious'); ok('brand impersonation + apk → malicious');
  r = await post('/api/url', {}); assert.equal(r.status, 400); ok('empty url rejected (400)');

  // --- /api/analyze (camera path)
  r = await post('/api/analyze', { content: 'Hello, just some text', source: 'camera' });
  assert.equal(r.body.scan.verdict, 'safe'); assert.equal(r.body.scan.source, 'camera'); ok('plain text from camera → safe');
  r = await post('/api/analyze', { content: 'https://bit.ly/3xYz' });
  assert.notEqual(r.body.scan.verdict, 'malicious'); ok('shortener → not malicious (' + r.body.scan.verdict + ')');

  // --- /api/upload with real QR images
  r = await upload(base, await qrPng('https://github.com/anthropics'));
  let b = await r.json(); assert.equal(r.status, 200); assert.equal(b.scan.content, 'https://github.com/anthropics'); assert.equal(b.scan.verdict, 'safe');
  ok('uploaded PNG QR decoded server-side → safe');

  r = await upload(base, await qrPng('http://203.0.113.9/bank/login?verify=1'));
  b = await r.json(); assert.equal(b.scan.verdict, 'malicious'); ok('uploaded malicious QR → malicious');

  const jpg = await sharp(await qrPng('https://example.com/ok')).jpeg({ quality: 70 }).toBuffer();
  r = await upload(base, jpg, 'qr.jpg', 'image/jpeg'); b = await r.json();
  assert.equal(b.scan.content, 'https://example.com/ok'); ok('JPEG QR decoded');

  const inv = await qrPng('https://inverted.example.org', { color: { dark: '#ffffffff', light: '#000000ff' } });
  r = await upload(base, inv); b = await r.json(); assert.equal(r.status, 200); ok('inverted (light-on-dark) QR decoded');

  const photo = await sharp({ create: { width: 900, height: 700, channels: 3, background: '#a0b0c0' } })
    .composite([{ input: await qrPng('https://in-a-photo.example.com'), left: 400, top: 250 }]).rotate(8, { background: '#a0b0c0' }).png().toBuffer();
  r = await upload(base, photo); b = await r.json(); assert.equal(r.status, 200); ok('QR embedded in larger rotated image decoded');

  const blank = await sharp({ create: { width: 200, height: 200, channels: 3, background: '#fff' } }).png().toBuffer();
  r = await upload(base, blank); assert.equal(r.status, 422); assert.ok((await r.json()).error.includes('No QR code')); ok('image without QR → 422 with message');
  r = await upload(base, Buffer.from('not an image'), 'x.txt', 'text/plain'); assert.equal(r.status, 400); ok('non-image rejected (400)');
  r = await upload(base, Buffer.from('garbage'), 'x.png', 'image/png'); assert.equal(r.status, 422); ok('corrupt image → 422');

  // --- history, stats, alerts, settings
  r = await j('/api/history'); const total = r.body.scans.length; assert.ok(total >= 9); ok(`history has ${total} records`);
  r = await j('/api/stats'); assert.equal(r.body.total, total);
  assert.equal(r.body.safe + r.body.suspicious + r.body.malicious, total);
  assert.equal(r.body.activity.length, 7); assert.equal(r.body.activity[6].safe + r.body.activity[6].suspicious + r.body.activity[6].malicious, total);
  ok('dashboard stats match history; today bucket correct');
  r = await j('/api/alerts'); assert.ok(r.body.alerts.every((a) => a.verdict !== 'safe')); ok('alerts only contain threats');

  r = await j('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sensitivity: 'low' }) });
  assert.equal(r.body.sensitivity, 'low');
  r = await post('/api/url', { url: 'https://free-prize.example.tk/claim' });
  assert.equal(r.body.scan.sensitivity, 'low'); assert.equal(r.body.scan.verdict, 'suspicious'); ok('sensitivity setting applied by analyzer');
  r = await j('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sensitivity: 'bogus' }) });
  assert.equal(r.status, 400); ok('invalid sensitivity rejected');
  await j('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sensitivity: 'medium' }) });

  // --- reports
  for (const [fmt, ct] of [['txt', 'text/plain'], ['csv', 'text/csv'], ['json', 'application/json']]) {
    const res = await fetch(`${base}/api/report?format=${fmt}`);
    assert.equal(res.status, 200); assert.ok(res.headers.get('content-type').startsWith(ct));
    assert.ok(/attachment; filename="qr-shield-report-/.test(res.headers.get('content-disposition')));
    const text = await res.text(); assert.ok(text.includes('203.0.113.9'));
  }
  ok('TXT / CSV / JSON reports download with attachment headers and include scans');

  // --- delete & persistence
  r = await j('/api/history'); const id = r.body.scans[0].id; const before = r.body.scans.length;
  r = await j('/api/history/' + id, { method: 'DELETE' }); assert.equal(r.status, 200);
  r = await j('/api/history/' + id, { method: 'DELETE' }); assert.equal(r.status, 404); ok('delete one record (+404 on repeat)');
  const onDisk = JSON.parse(fs.readFileSync(path.join(process.env.DATA_DIR, 'scans.json'), 'utf8')); assert.equal(onDisk.length, before - 1);
  ok('data persisted to disk');
  r = await j('/api/history', { method: 'DELETE' }); r = await j('/api/stats'); assert.equal(r.body.total, 0); ok('clear all → stats reset to 0');

  // --- static frontend
  const html = await fetch(base + '/').then((x) => x.text()); assert.ok(html.includes('QR Shield')); ok('frontend served at /');

  console.log(`\nAll ${n} checks passed.`);
  server.close(); process.exit(0);
})().catch((e) => { console.error('\nTEST FAILED:', e); process.exit(1); });
