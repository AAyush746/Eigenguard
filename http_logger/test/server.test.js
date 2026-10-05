/**
 * Tests for the HTTP request logger.
 *
 * Uses node:test so no extra dependencies are required.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// The logger writes to a directory chosen at require time, so point it at a
// temporary one before loading the module.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eigenguard-logger-'));
process.env.EG_DATA_DIR = tmpDir;

const app = require('../server');

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/** Wait for the async append to land before asserting on the log. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 150));

test('serves a demo endpoint', async () => {
  const response = await fetch(`${baseUrl}/api/demo/items`);
  assert.strictEqual(response.status, 200);
  const body = await response.json();
  assert.strictEqual(body.items.length, 5);
});

test('logs requests as newline-delimited JSON', async () => {
  await fetch(`${baseUrl}/api/demo/status`);
  await settle();

  const raw = fs.readFileSync(path.join(tmpDir, 'http_requests.ndjson'), 'utf8');
  const lines = raw.split('\n').filter(Boolean);
  assert.ok(lines.length > 0, 'expected at least one logged request');

  for (const line of lines) {
    const record = JSON.parse(line); // throws if a line is malformed
    assert.ok(record.timestamp);
    assert.ok(record.method);
    assert.ok(record.status);
  }
});

test('records 404 responses instead of dropping them', async () => {
  await fetch(`${baseUrl}/definitely-not-a-real-path`);
  await settle();

  const response = await fetch(`${baseUrl}/api/requests?limit=50`);
  const body = await response.json();
  const notFound = body.results.find((r) => r.path === '/definitely-not-a-real-path');
  assert.ok(notFound, 'the 404 was not recorded');
  assert.strictEqual(notFound.status, 404);
});

test('splits path from query string', async () => {
  await fetch(`${baseUrl}/api/demo/items?page=2&limit=10`);
  await settle();

  const response = await fetch(`${baseUrl}/api/requests?limit=50`);
  const body = await response.json();
  const record = body.results.find((r) => r.path === '/api/demo/items');
  assert.ok(record, 'path column should not include the query string');
  assert.ok(record.query.includes('page=2'));
});

test('aggregates stats per method and status', async () => {
  const response = await fetch(`${baseUrl}/api/stats`);
  const stats = await response.json();

  assert.ok(stats.totalRequests > 0);
  assert.ok(stats.methods.some((m) => m.name === 'GET'));
  assert.ok(stats.statuses.some((s) => s.name === '200'));
  assert.ok(stats.avgResponseMs >= 0);
});

test('exports the raw log as NDJSON', async () => {
  const response = await fetch(`${baseUrl}/api/export`);
  assert.match(response.headers.get('content-type'), /ndjson/);

  const text = await response.text();
  const lines = text.split('\n').filter(Boolean);
  assert.ok(lines.length > 0);
  JSON.parse(lines[0]);
});

test('clear empties the log and resets counters', async () => {
  await fetch(`${baseUrl}/api/clear`, { method: 'POST' });
  await settle();

  const stats = await (await fetch(`${baseUrl}/api/stats`)).json();
  assert.strictEqual(stats.totalRequests, 0);
  assert.strictEqual(fs.readFileSync(path.join(tmpDir, 'http_requests.ndjson'), 'utf8'), '');
});