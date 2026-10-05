/**
 * EigenGuard HTTP request logger.
 *
 * Logs every request to a newline-delimited JSON file, which is what the ML
 * pipeline reads. NDJSON is used deliberately: the original implementation
 * read the whole log into memory and rewrote it on every request, which is
 * O(n) per request and corrupts the file if the process dies mid-write.
 *
 * Uses only Node's built-in http module, so `npm install` is not required.
 *
 * Endpoints:
 *   /api/requests   - recent logged requests
 *   /api/stats      - aggregates for the dashboard
 *   /api/export     - NDJSON download for the ML pipeline
 *   /api/clear      - truncate the log
 */
const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.EG_DATA_DIR || path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(DATA_DIR, 'http_requests.ndjson');

fs.mkdirSync(DATA_DIR, { recursive: true });

// Running counters backing the stats endpoint.
const counters = {
  total: 0,
  bytes: 0,
  totalResponseMs: 0,
  byMethod: Object.create(null),
  byStatus: Object.create(null),
  byIp: Object.create(null),
  byUserAgent: Object.create(null),
};

function bump(bucket, key) {
  if (key === undefined || key === null) return;
  bucket[key] = (bucket[key] || 0) + 1;
}

/** Normalise ::ffff:127.0.0.1 to 127.0.0.1. */
function normaliseIp(address) {
  return (address || 'unknown').replace(/^::ffff:/, '');
}

/** Build the log record for a finished request. */
function buildRecord(req, res, responseTime, responseSize, status) {
  const [rawPath, query = ''] = req.url.split('?');
  return {
    timestamp: new Date().toISOString(),
    ip: normaliseIp(req.socket.remoteAddress),
    method: req.method,
    path: rawPath,
    query,
    contentLength: Number(req.headers['content-length'] || 0),
    userAgent: req.headers['user-agent'] || 'unknown',
    referer: req.headers.referer || '',
    status,
    responseTime: Math.round(responseTime * 1000) / 1000,
    responseSize,
  };
}

/**
 * The logger's own introspection endpoints are not "traffic", so they are
 * excluded from both the counters and the dataset. Otherwise a dashboard
 * polling /api/stats would show up as synthetic attack-like activity.
 */
const CONTROL_PATHS = new Set([
  '/api/requests',
  '/api/stats',
  '/api/export',
  '/api/clear',
]);

function recordRequest(record) {
  if (CONTROL_PATHS.has(record.path)) return;

  counters.total += 1;
  counters.bytes += record.responseSize;
  counters.totalResponseMs += record.responseTime;
  bump(counters.byMethod, record.method);
  bump(counters.byStatus, String(record.status));
  bump(counters.byIp, record.ip);
  bump(counters.byUserAgent, record.userAgent);

  // Append-only: one line per request, never a full rewrite.
  fs.appendFile(LOG_FILE, `${JSON.stringify(record)}\n`, (err) => {
    if (err) console.error('failed to append request log:', err.message);
  });
}

/** Send a JSON response and log it. */
function sendJson(req, res, status, body) {
  const payload = JSON.stringify(body);
  const started = process.hrtime.bigint();
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);

  const responseTime = Number(process.hrtime.bigint() - started) / 1e6;
  recordRequest(buildRecord(req, res, responseTime, Buffer.byteLength(payload), status));
  console.log(`${req.method} ${req.url} ${status} ${responseTime.toFixed(1)}ms`);
}

/** Read the log back. `limit` of 0 or undefined returns everything. */
async function readLog(limit) {
  const raw = await fsp.readFile(LOG_FILE, 'utf8').catch(() => '');
  const lines = raw.split('\n').filter(Boolean);
  const slice = limit ? lines.slice(-limit) : lines;
  const records = [];
  for (const line of slice) {
    try {
      records.push(JSON.parse(line));
    } catch {
      // Skip a torn line rather than failing the whole read.
    }
  }
  return records;
}

function top(bucket, n) {
  return Object.entries(bucket)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([name, count]) => ({ name, count }));
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;

  if (pathname === '/api/requests' && req.method === 'GET') {
    const limit = Math.min(Number(url.searchParams.get('limit')) || 100, 1000);
    const requests = await readLog(limit);
    return sendJson(req, res, 200, {
      total: counters.total,
      results: requests.reverse(),
    });
  }

  if (pathname === '/api/stats' && req.method === 'GET') {
    return sendJson(req, res, 200, {
      totalRequests: counters.total,
      totalBytes: counters.bytes,
      avgResponseMs: counters.total
        ? Math.round((counters.totalResponseMs / counters.total) * 1000) / 1000
        : 0,
      uniqueIps: Object.keys(counters.byIp).length,
      methods: top(counters.byMethod, 10),
      statuses: top(counters.byStatus, 10),
      topIps: top(counters.byIp, 10),
      topUserAgents: top(counters.byUserAgent, 10),
    });
  }

  if (pathname === '/api/export' && req.method === 'GET') {
    await new Promise((resolve) => {
      res.writeHead(200, {
        'Content-Type': 'application/x-ndjson',
        'Content-Disposition':
          'attachment; filename="eigenguard_http_requests.ndjson"',
      });
      const stream = fs.createReadStream(LOG_FILE);
      stream.on('error', () => res.end());
      stream.pipe(res);
      stream.on('end', resolve);
    });
    return undefined;
  }

  if (pathname === '/api/clear' && req.method === 'POST') {
    await fsp.writeFile(LOG_FILE, '');
    counters.total = 0;
    counters.bytes = 0;
    counters.totalResponseMs = 0;
    for (const key of Object.keys(counters)) {
      if (key.startsWith('by')) counters[key] = Object.create(null);
    }
    return sendJson(req, res, 200, { success: true });
  }

  if (pathname === '/api/demo/items') {
    return sendJson(req, res, 200, {
      items: Array.from({ length: 5 }, (_, i) => ({ id: i, name: `item-${i}` })),
    });
  }

  if (pathname === '/api/demo/status') {
    return sendJson(req, res, 200, {
      status: 'ok',
      uptimeSeconds: Math.round(process.uptime()),
    });
  }

  // 404s are logged too: scanners spend most of their time probing paths
  // that do not exist, and those probes are exactly what we want to see.
  return sendJson(req, res, 404, { error: 'not found' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('request failed:', err);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal error' }));
    }
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`EigenGuard HTTP logger on http://localhost:${PORT}`);
    console.log(`Writing request log to ${LOG_FILE}`);
  });
}

module.exports = server;
module.exports.readLog = readLog;
module.exports.LOG_FILE = LOG_FILE;