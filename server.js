#!/usr/bin/env node
/*
 * Local HTTP server for the Roodie APIs.
 *
 * The two engines (xeno-api.js and claims-api.js) already speak HTTP semantics through a
 * fetch()-style interface. This file puts a real socket in front of them so you can hit them
 * with curl, Postman or any HTTP client:
 *
 *   node server.js            start on http://127.0.0.1:3000
 *   node server.js --fresh    wipe saved data and re-seed first
 *   PORT=4000 node server.js  pick another port
 *
 *   Roodie Insuretech API  →  http://localhost:3000/insuretech/v1
 *   Xeno Shield API        →  http://localhost:3000/shield/v1
 *
 * No dependencies; needs Node 18+. It binds to 127.0.0.1 only, so it is not reachable from
 * other machines. State is saved to ./data/*.json between runs.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const xeno = require('./xeno-api.js');
const insuretech = require('./claims-api.js');

const MAX_BODY_BYTES = 1024 * 1024;

function fileStorage(dir, name) {
  const file = path.join(dir, name + '.json');
  return {
    load() { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; } },
    save(state) { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(file, JSON.stringify(state)); },
    remove() { try { fs.unlinkSync(file); } catch (e) { /* nothing saved yet */ } },
  };
}

function problem(status, slug, title, detail, path_) {
  return {
    status,
    body: { type: 'https://api.roodie.local/problems/' + slug, title, status, detail, instance: path_ },
  };
}

/** Build the HTTP server without starting it (handy for tests). */
function createApp(options) {
  const opts = options || {};
  const dir = opts.dataDir || path.join(__dirname, 'data');
  const log = opts.log === undefined ? console.log : opts.log;
  const serviceOpts = { latency: 0, ...(opts.rateLimit === false ? { rateLimit: false } : {}) };

  const stores = { shield: fileStorage(dir, 'shield'), insuretech: fileStorage(dir, 'insuretech') };
  if (opts.fresh) Object.values(stores).forEach((s) => s.remove());

  const mounts = [
    { prefix: '/shield', name: 'Xeno Shield API', svc: xeno.createService({ ...serviceOpts, storage: stores.shield }) },
    { prefix: '/insuretech', name: 'Roodie Insuretech API', svc: insuretech.createService({ ...serviceOpts, storage: stores.insuretech }) },
  ];

  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      // Keep reading (and discarding) an oversized upload so the client can receive our 413
      // instead of a dropped connection.
      req.on('data', (c) => {
        size += c.length;
        if (size <= MAX_BODY_BYTES) chunks.push(c);
      });
      req.on('end', () => {
        if (size > MAX_BODY_BYTES) reject(Object.assign(new Error('too large'), { code: 'TOO_LARGE' }));
        else resolve(Buffer.concat(chunks).toString('utf8'));
      });
      req.on('error', reject);
    });
  }

  function send(res, status, headers, body) {
    const payload = body === undefined || status === 204 || status === 304 ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (payload && !h['content-type']) h['content-type'] = 'application/json; charset=utf-8';
    res.writeHead(status, h);
    res.end(payload);
  }

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    let status = 500;
    let shownPath = req.url;
    try {
      const url = new URL(req.url, 'http://localhost');
      shownPath = url.pathname + url.search;

      if (url.pathname === '/health') {
        status = 200;
        return send(res, 200, {}, { ok: true });
      }
      if (url.pathname === '/') {
        status = 200;
        return send(res, 200, {}, {
          name: 'Roodie APIs (local)',
          apis: mounts.map((m) => ({ name: m.name, base: `http://${req.headers.host}${m.prefix}/v1` })),
          docs: 'See the curl guide PDF, or run: source scripts/curl-helpers.sh',
        });
      }

      const mount = mounts.find((m) => url.pathname === m.prefix || url.pathname.startsWith(m.prefix + '/'));
      if (!mount) {
        const p = problem(404, 'not-found', 'Unknown API', `Nothing is mounted at ${url.pathname}. Try /insuretech/v1 or /shield/v1.`, url.pathname);
        status = p.status;
        return send(res, p.status, { 'content-type': 'application/problem+json' }, p.body);
      }

      const hasBody = !['GET', 'HEAD'].includes(req.method);
      const body = hasBody ? await readBody(req) : undefined;
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = Array.isArray(v) ? v.join(', ') : v;

      const inner = (url.pathname.slice(mount.prefix.length) || '/') + url.search;
      const out = await mount.svc.fetch(inner, { method: req.method, headers, body: body || undefined });
      status = out.status;
      const outHeaders = {};
      out.headers.forEach((v, k) => { outHeaders[k] = v; });
      const buf = Buffer.from(await out.arrayBuffer());
      res.writeHead(out.status, outHeaders);
      res.end(out.status === 204 || out.status === 304 || req.method === 'HEAD' ? undefined : buf);
    } catch (e) {
      if (e && e.code === 'TOO_LARGE') {
        const p = problem(413, 'payload-too-large', 'Payload too large', `Request bodies are limited to ${MAX_BODY_BYTES} bytes.`, shownPath);
        status = 413;
        if (!res.headersSent) send(res, 413, { 'content-type': 'application/problem+json', connection: 'close' }, p.body);
        return;
      }
      console.error('[server]', e);
      const p = problem(500, 'internal-error', 'Internal error', 'The server hit an unexpected error.', shownPath);
      status = 500;
      if (!res.headersSent) send(res, 500, { 'content-type': 'application/problem+json' }, p.body);
      else res.end();
    } finally {
      if (log) log(`${req.method.padEnd(7)} ${String(status)}  ${String(Date.now() - started).padStart(3)}ms  ${shownPath}`);
    }
  });

  return { server, mounts };
}

function main() {
  const port = Number(process.env.PORT) || 3000;
  const host = '127.0.0.1';
  const { server } = createApp({ fresh: process.argv.includes('--fresh'), rateLimit: process.env.RATE_LIMIT === 'off' ? false : undefined });
  server.listen(port, host, () => {
    const base = `http://localhost:${port}`;
    console.log(`
  Roodie APIs are running (local only, ${host})

  Roodie Insuretech API   ${base}/insuretech/v1
  Xeno Shield API         ${base}/shield/v1
  Health check            ${base}/health

  Demo tokens   claimant_demo_key · adjuster_demo_key · xeno_demo_key
  Try it        curl ${base}/insuretech/v1/claims?risk=high
  Helpers       source scripts/curl-helpers.sh

  Data is saved in ./data (use --fresh to reset).  Ctrl+C to stop.
`);
  });
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') console.error(`Port ${port} is already in use. Try: PORT=${port + 1} node server.js`);
    else console.error(e);
    process.exit(1);
  });
}

if (require.main === module) main();
module.exports = { createApp };
