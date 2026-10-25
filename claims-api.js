/*!
 * Roodie Insuretech API  ·  v2026-10-24
 * By Jonathan (Roodie77).
 *
 * An insurance claims engine: policies, claim intake, coverage maths, transparent
 * fraud scoring, straight-through processing, adjuster decisions, payouts and appeals.
 *
 * Like Xeno Shield it is a complete HTTP-semantics engine that runs in the page (or in
 * Node): routing, role-based auth, validation, optimistic concurrency, idempotency,
 * pagination and rate limiting. `service.fetch()` has the same signature as window.fetch.
 *
 *   ClaimsAPI.service.fetch('/v1/claims?risk=high&sort=-fraud_score')
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ClaimsAPI = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /* ───────────────────────── constants ───────────────────────── */

  const API_VERSION = '2026-10-24';
  const BASE = 'https://api.claims.local';
  const PROBLEM_NS = BASE + '/problems/';
  const STORE_KEY = 'xeno-claims-v1';
  const TOKENS = { claimant_demo_key: 'claimant', adjuster_demo_key: 'adjuster' };
  const ROLE_RANK = { claimant: 1, adjuster: 2 };
  const DAY = 86400000;

  const PRODUCTS = ['auto', 'home', 'health', 'travel'];
  const PRODUCT_COVERAGES = {
    auto: ['collision', 'theft', 'fire', 'glass', 'liability'],
    home: ['fire', 'water', 'theft', 'storm', 'liability'],
    health: ['medical', 'dental'],
    travel: ['trip-cancellation', 'baggage', 'medical'],
  };
  const CLAIM_TYPES = [...new Set(Object.values(PRODUCT_COVERAGES).flat())];
  const EXCLUSIONS = ['racing', 'intentional-damage', 'flood', 'war'];
  const EXCLUSION_PATTERNS = {
    racing: /\b(?:rac(?:e|ed|es|ing)|track day|drag strip)\b/i,
    'intentional-damage': /\b(?:intentional(?:ly)?|on purpose|deliberate(?:ly)?)\b/i,
    flood: /\bflood(?:ed|ing|s)?\b/i,
    war: /\b(?:war|invasion|riot)\b/i,
  };
  const TYPICAL_AMOUNT = {
    collision: 3500, theft: 2500, fire: 15000, glass: 400, liability: 8000, water: 5000, storm: 6000,
    medical: 2000, dental: 600, 'trip-cancellation': 1500, baggage: 700,
  };

  const POLICY_STATUSES = ['active', 'lapsed', 'cancelled'];
  const POLICY_TRANSITIONS = { active: ['lapsed', 'cancelled'], lapsed: ['active', 'cancelled'], cancelled: [] };
  const CLAIM_STATUSES = ['under_review', 'info_requested', 'siu_review', 'approved', 'denied', 'appealed', 'paid'];
  const ROUTING_PATHS = ['straight-through', 'adjuster', 'siu', 'auto-denied'];
  const RISK_BANDS = ['low', 'medium', 'high'];
  const DOC_KINDS = ['photo', 'police-report', 'invoice', 'medical-report', 'repair-estimate', 'other'];

  // What an adjuster can do, and from which states. Anything else is a 409.
  const DECISIONS = {
    approve: { to: 'approved', from: ['under_review', 'siu_review', 'appealed'] },
    deny: { to: 'denied', from: ['under_review', 'siu_review', 'appealed'] },
    request_info: { to: 'info_requested', from: ['under_review', 'siu_review', 'appealed'] },
    escalate: { to: 'siu_review', from: ['under_review', 'appealed'] },
  };
  const EDITABLE_CLAIM_STATES = ['under_review', 'info_requested', 'siu_review'];
  const APPEAL_WINDOW_DAYS = 30;
  const FILING_WINDOW_DAYS = 60;

  const RATE_CAPACITY = 60;
  const RATE_REFILL_PER_SEC = 10;
  const IDEMPOTENCY_TTL_MS = 24 * 3600 * 1000;

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
  const money = (n) => Math.round(n * 100) / 100;
  const ymd = (ms) => new Date(ms).toISOString().slice(0, 10);
  const dayMs = (d) => Date.parse(d + 'T00:00:00Z');
  const daysBetween = (a, b) => Math.round((dayMs(b) - dayMs(a)) / DAY); // b minus a

  function fnv(str, seed) {
    let h = seed >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h;
  }
  const etagOf = (r) => `"${r.version}-${fnv(r.id + ':' + r.version, 5).toString(16).padStart(8, '0')}"`;

  function pick(obj, paths) {
    const out = {};
    for (const p of paths) if (p in obj) out[p] = obj[p];
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

  /** Small validation kit shared by every resource. */
  function makeCheck(input, errors) {
    const err = (pointer, code, message) => errors.push({ pointer, code, message });
    const missing = (key, out, o) => {
      if (o.required) err('/' + key, 'required', `${key} is required.`);
      else if (o.def !== undefined) out[key] = o.def;
    };
    return {
      err,
      unknown(allowed, readOnly) {
        for (const k of Object.keys(input)) {
          if (readOnly && readOnly.has(k)) err('/' + k, 'read_only', `"${k}" is assigned by the server and cannot be written.${o_hint(k)}`);
          else if (!allowed.has(k)) err('/' + k, 'unknown_field', `"${k}" is not a writable field.`);
        }
      },
      str(key, out, o) {
        const val = input[key];
        if (val === undefined || val === null) return missing(key, out, o);
        if (typeof val !== 'string') return err('/' + key, 'type', `${key} must be a string.`);
        const s = val.trim();
        if (s.length < (o.min || 0) || s.length > o.max) return err('/' + key, 'length', `${key} must be ${o.min || 0}–${o.max} characters.`);
        if (o.pattern && !o.pattern.test(s)) return err('/' + key, 'format', o.patternMsg || `${key} has an invalid format.`);
        out[key] = s;
      },
      num(key, out, o) {
        const v = input[key];
        if (v === undefined || v === null) return missing(key, out, o);
        if (typeof v !== 'number' || !Number.isFinite(v) || v < o.min || v > o.max || (o.int && !Number.isInteger(v))) {
          return err('/' + key, 'range', `${key} must be ${o.int ? 'an integer' : 'a number'} between ${o.min} and ${o.max}.`);
        }
        out[key] = o.int ? v : money(v);
      },
      date(key, out, o) {
        const v = input[key];
        if (v === undefined || v === null) return missing(key, out, o);
        if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v + 'T00:00:00Z')) || ymd(dayMs(v)) !== v) {
          return err('/' + key, 'format', `${key} must be a real calendar date (YYYY-MM-DD).`);
        }
        out[key] = v;
      },
      enm(key, out, list, def) {
        const v = input[key];
        if (v === undefined || v === null) { if (def === undefined) err('/' + key, 'required', `${key} is required.`); else out[key] = def; return; }
        if (!list.includes(v)) return err('/' + key, 'enum', `${key} must be one of: ${list.join(', ')}.`);
        out[key] = v;
      },
      list(key, out, allowed, o) {
        const v = input[key];
        if (v === undefined || v === null) { if (o.min) err('/' + key, 'required', `${key} is required.`); else out[key] = []; return; }
        if (!Array.isArray(v) || v.length < (o.min || 0) || v.length > o.max) return err('/' + key, 'type', `${key} must be an array of ${o.min || 0}–${o.max} items.`);
        const bad = v.findIndex((x) => !allowed.includes(x));
        if (bad !== -1) return err(`/${key}/${bad}`, 'enum', `each item of ${key} must be one of: ${allowed.join(', ')}.`);
        if (new Set(v).size !== v.length) return err('/' + key, 'unique', `${key} must be unique.`);
        out[key] = [...v];
      },
    };
  }

  // Tells a client where to go instead, for the fields people most often try to write directly.
  function o_hint(key) {
    if (key === 'status') return ' Use POST /v1/claims/{id}/decision, /pay or /appeal to move a claim.';
    return '';
  }

  /* ───────────────────────── claim assessment ───────────────────────── */

  /**
   * The heart of the engine. Given a claim and its policy, work out: is it eligible, what would
   * it pay, how suspicious is it, and who should handle it. Everything is returned so a human
   * (or a regulator) can see exactly why.
   */
  function assessClaim(c, policy, others, filedMs, committed) {
    const rules = [];
    const rule = (id, hard, passed, detail) => rules.push({ rule: id, hard, passed, detail });
    const today = ymd(filedMs);
    const lateDays = daysBetween(c.incident_date, today);

    rule('policy.active', true, policy.status === 'active', policy.status === 'active' ? 'Policy is active.' : `Policy status is "${policy.status}".`);
    const inForce = c.incident_date >= policy.start_date && c.incident_date <= policy.end_date;
    rule('policy.in-force', true, inForce, inForce
      ? `Incident on ${c.incident_date} falls inside ${policy.start_date} → ${policy.end_date}.`
      : `Incident on ${c.incident_date} is outside the policy period ${policy.start_date} → ${policy.end_date}.`);
    const waitEnd = ymd(dayMs(policy.start_date) + policy.waiting_period_days * DAY);
    const waitOk = policy.waiting_period_days === 0 || c.incident_date >= waitEnd;
    rule('policy.waiting-period', true, waitOk, policy.waiting_period_days === 0
      ? 'No waiting period.'
      : waitOk ? `Waiting period of ${policy.waiting_period_days} days had ended by ${waitEnd}.` : `Cover only starts after the ${policy.waiting_period_days}-day waiting period (${waitEnd}).`);
    const covered = policy.coverages.includes(c.type);
    rule('coverage.type-covered', true, covered, covered ? `"${c.type}" is covered.` : `"${c.type}" is not covered by this policy (covers: ${policy.coverages.join(', ')}).`);
    const remaining = money(policy.limit - committed);
    rule('limit.remaining', true, remaining > 0, remaining > 0 ? `${remaining} of the ${policy.limit} limit remains.` : 'The policy limit is exhausted.');
    rule('filing.within-window', true, lateDays <= FILING_WINDOW_DAYS, lateDays <= FILING_WINDOW_DAYS
      ? `Filed ${lateDays} day${lateDays === 1 ? '' : 's'} after the incident (window is ${FILING_WINDOW_DAYS}).`
      : `Filed ${lateDays} days after the incident; the window is ${FILING_WINDOW_DAYS}.`);
    const excluded = policy.exclusions.find((e) => EXCLUSION_PATTERNS[e] && EXCLUSION_PATTERNS[e].test(c.description));
    // Soft rule: wording can mislead, so this sends the claim to a human instead of auto-denying it.
    rule('coverage.not-excluded', false, !excluded, excluded ? `The description suggests the "${excluded}" exclusion may apply.` : 'No exclusion language found.');

    const afterDeductible = Math.max(0, money(c.amount_claimed - policy.deductible));
    const insurerShare = money(afterDeductible * (1 - policy.coinsurance_pct / 100));
    const payable = money(Math.min(insurerShare, Math.max(0, remaining)));
    const coverage = {
      limit: policy.limit, remaining_limit: remaining, deductible: policy.deductible, coinsurance_pct: policy.coinsurance_pct,
      amount_after_deductible: afterDeductible, insurer_share: insurerShare, payable_estimate: payable, capped_by_limit: insurerShare > remaining,
    };

    const flags = [];
    const flag = (code, weight, detail) => flags.push({ code, weight, detail });
    if (others.some((o) => o.type === c.type && Math.abs(daysBetween(o.incident_date, c.incident_date)) <= 3)) flag('possible-duplicate', 35, 'Another claim of the same type on this policy has an incident date within 3 days.');
    const sinceStart = daysBetween(policy.start_date, c.incident_date);
    if (sinceStart >= 0 && sinceStart <= 30) flag('early-claim', 25, `Incident happened ${sinceStart} days after the policy started.`);
    if (others.length >= 3) flag('claim-frequency', 20, `${others.length} other claims already exist on this policy.`);
    if (c.amount_claimed >= 0.9 * policy.limit) flag('near-limit', 20, 'Claim is 90% or more of the policy limit.');
    if (TYPICAL_AMOUNT[c.type] && c.amount_claimed > 3 * TYPICAL_AMOUNT[c.type]) flag('amount-outlier', 15, `More than 3× the typical "${c.type}" claim (${TYPICAL_AMOUNT[c.type]}).`);
    if (/\b(?:total loss|cash only|no witnesses?|no police report|urgent(?:ly)?|lost (?:all )?receipts?)\b/i.test(c.description)) flag('suspicious-language', 12, 'Description contains wording that correlates with fraudulent claims.');
    if (lateDays > 45) flag('late-filing', 10, `Filed ${lateDays} days after the incident.`);
    if (c.amount_claimed >= 1000 && c.amount_claimed % 100 === 0) flag('round-amount', 8, 'Large, perfectly round amount.');
    const score = Math.min(100, flags.reduce((a, f) => a + f.weight, 0));
    const band = score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';

    const hardFails = rules.filter((r) => r.hard && !r.passed);
    let path, reason;
    if (hardFails.length) { path = 'auto-denied'; reason = 'Failed eligibility: ' + hardFails.map((r) => r.rule).join(', ') + '.'; }
    else if (band === 'high') { path = 'siu'; reason = `Fraud score ${score} is in the high band, so special investigations must review it.`; }
    else if (rules.some((r) => !r.passed)) { path = 'adjuster'; reason = 'An eligibility check needs human judgment: ' + rules.filter((r) => !r.passed).map((r) => r.rule).join(', ') + '.'; }
    else if (band === 'low' && payable > 0 && c.amount_claimed <= policy.auto_approve_limit) { path = 'straight-through'; reason = `Eligible, low fraud risk (${score}) and within the ${policy.auto_approve_limit} auto-approve limit.`; }
    else if (payable <= 0) { path = 'adjuster'; reason = 'Nothing is payable after the deductible, so an adjuster should confirm.'; }
    else if (band !== 'low') { path = 'adjuster'; reason = `Fraud band is "${band}" (score ${score}).`; }
    else { path = 'adjuster'; reason = `Amount ${c.amount_claimed} exceeds the policy auto-approve limit of ${policy.auto_approve_limit}.`; }

    return { eligibility: rules, coverage, fraud: { score, band, flags }, routing: { path, reason } };
  }

  /* ───────────────────────── presenters ───────────────────────── */

  const presentClaim = (r) => ({
    id: r.id, object: 'claim', claim_number: r.claim_number, policy_id: r.policy_id, type: r.type, incident_date: r.incident_date,
    amount_claimed: r.amount_claimed, description: r.description, status: r.status, assessment: clone(r.assessment || {}),
    approved_amount: r.approved_amount, paid_amount: r.paid_amount, paid_at: r.paid_at, payment_reference: r.payment_reference,
    decision: r.decision ? clone(r.decision) : null, documents: [...(r.documents || [])], appeal_count: r.appeal_count, appeal_reason: r.appeal_reason,
    filed_at: r.filed_at, version: r.version, created_at: r.created_at, updated_at: r.updated_at, deleted_at: r.deleted_at,
    links: { self: `/v1/claims/${r.id}`, history: `/v1/claims/${r.id}/history`, policy: `/v1/policies/${r.policy_id}` },
  });

  /* ───────────────────────── service ───────────────────────── */

  function createService(opts) {
    opts = opts || {};
    const storage = opts.storage || makeStorage();
    const latency = opts.latency === undefined ? [30, 110] : opts.latency;
    const loaded = storage.load();
    const needsSeed = !loaded || loaded.v !== 1 || !loaded.claims;
    let state = needsSeed ? { v: 1, policies: {}, claims: {}, history: {}, idem: {}, counters: { claim: 0 } } : loaded;
    const limiter = { tokens: RATE_CAPACITY, t: Date.now() };
    const save = () => storage.save(state);

    /* ── domain helpers ── */

    const liveClaims = () => Object.values(state.claims).filter((c) => !c.deleted_at);

    /** Money already promised or paid out on a policy (the "reserve"), optionally ignoring one claim. */
    function committedOn(policyId, excludeId) {
      return money(liveClaims()
        .filter((c) => c.policy_id === policyId && c.id !== excludeId && (c.status === 'approved' || c.status === 'paid'))
        .reduce((a, c) => a + (c.paid_amount != null ? c.paid_amount : c.approved_amount || 0), 0));
    }

    function usageOf(policy) {
      const mine = liveClaims().filter((c) => c.policy_id === policy.id);
      const paid = money(mine.filter((c) => c.status === 'paid').reduce((a, c) => a + (c.paid_amount || 0), 0));
      const reserved = money(mine.filter((c) => c.status === 'approved').reduce((a, c) => a + (c.approved_amount || 0), 0));
      return { paid, reserved, remaining_limit: money(policy.limit - paid - reserved), claims: mine.length };
    }

    const presentPolicy = (p) => ({
      id: p.id, object: 'policy', holder: p.holder, product: p.product, coverages: [...p.coverages], limit: p.limit, deductible: p.deductible,
      coinsurance_pct: p.coinsurance_pct, premium_annual: p.premium_annual, start_date: p.start_date, end_date: p.end_date, status: p.status,
      exclusions: [...p.exclusions], waiting_period_days: p.waiting_period_days, auto_approve_limit: p.auto_approve_limit,
      usage: usageOf(p), version: p.version, created_at: p.created_at, updated_at: p.updated_at,
      links: { self: `/v1/policies/${p.id}`, history: `/v1/policies/${p.id}/history`, claims: `/v1/claims?policy_id=${p.id}` },
    });

    function record(rec, type, reqId, changes, actor) {
      const log = state.history[rec.id] || (state.history[rec.id] = []);
      log.push({ seq: log.length + 1, type, at: rec.updated_at, version: rec.version, actor: actor || 'system', request_id: reqId, changes: changes || null });
    }

    function precondition(req, rec) {
      const h = req.headers['if-match'];
      if (h === undefined) {
        throw new ApiError(428, 'precondition-required', 'Precondition required',
          'This write needs an If-Match header carrying the ETag from your last read, so two people cannot act on the same claim blindly.',
          { headers: { ETag: etagOf(rec) } });
      }
      if (h.trim() === '*') return;
      const sent = h.split(',').map((s) => s.trim().replace(/^W\//, ''));
      if (!sent.includes(etagOf(rec))) {
        throw new ApiError(412, 'precondition-failed', 'Precondition failed',
          `This record changed since you read it (it is now at version ${rec.version}). Re-fetch, review, and retry.`,
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

    const remember = (idem, res) => { if (idem.key) state.idem[idem.key] = { fp: idem.fp, at: Date.now(), status: res.status, headers: res.headers, body: clone(res.body) }; };

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
          throw new ApiError(410, 'gone', `${cfg.label} was withdrawn`, `${cfg.label} "${id}" was withdrawn at ${r.deleted_at}. An adjuster can restore it.`,
            { deleted_at: r.deleted_at, restore: `${cfg.base}/${id}/restore`, headers: { ETag: etagOf(r) } });
        }
        return r;
      };
      const ev = (name) => (cfg.events && cfg.events[name]) || name;

      function commit(rec, next, c) {
        if (cfg.canEdit) cfg.canEdit(rec);
        const prev = cfg.view(rec);
        const rules = cfg.rules(next, rec, c);
        if (rules.length) throw validationError(rules);
        const imm = (cfg.immutable || []).filter((k) => JSON.stringify(prev[k]) !== JSON.stringify(next[k]))
          .map((k) => ({ pointer: '/' + k, code: 'immutable', message: `"${k}" cannot be changed after creation.` }));
        if (imm.length) throw validationError(imm);
        if (cfg.transitions && next.status !== rec.status && !cfg.transitions[rec.status].includes(next.status)) {
          throw new ApiError(409, 'illegal-transition', 'Illegal status transition', `A ${cfg.label} cannot go from "${rec.status}" to "${next.status}".`,
            { from: rec.status, to: next.status, allowed: cfg.transitions[rec.status] });
        }
        const changes = diff(prev, next);
        if (!Object.keys(changes).length) return { status: 200, headers: { ETag: etagOf(rec), 'X-Change': 'none' }, body: cfg.present(rec) };
        cfg.apply(rec, next);
        rec.version += 1;
        rec.updated_at = iso();
        record(rec, ev('updated'), c.reqId, changes, c.role);
        save();
        return { status: 200, headers: { ETag: etagOf(rec) }, body: cfg.present(rec) };
      }

      return {
        find,
        list: (c) => listing(c, cfg.list),

        create(c) {
          const idem = idempotency(c);
          if (idem.replay) return idem.replay;
          const { value, errors } = cfg.validate(c.body);
          if (errors.length) throw validationError(errors);
          const rules = cfg.rules(value, null, c);
          if (rules.length) throw validationError(rules);
          const rec = cfg.build(value, c);
          state[cfg.key][rec.id] = rec;
          record(rec, ev('created'), c.reqId, null, c.role);
          if (cfg.afterCreate) cfg.afterCreate(rec, c);
          const res = { status: 201, headers: { Location: `${cfg.base}/${rec.id}`, ETag: etagOf(rec) }, body: cfg.present(rec) };
          remember(idem, res);
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
          return commit(rec, value, c);
        },

        patch(c) {
          const rec = find(c.params.id);
          precondition(c.req, rec);
          if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'A merge patch must be a JSON object.' }]);
          const { value, errors } = cfg.validate(mergePatch(cfg.view(rec), c.body));
          if (errors.length) throw validationError(errors);
          return commit(rec, value, c);
        },

        remove(c) {
          const rec = find(c.params.id, true);
          if (c.query.get('purge') === 'true' && cfg.noPurge) {
            throw new ApiError(409, 'retention-required', 'Records are retained', 'Claims are financial records and are never permanently deleted. Withdrawing one keeps it in the audit trail.');
          }
          if (rec.deleted_at) find(c.params.id); // throws 410
          precondition(c.req, rec);
          if (cfg.canDelete) cfg.canDelete(rec);
          rec.deleted_at = iso();
          rec.updated_at = rec.deleted_at;
          rec.version += 1;
          record(rec, ev('deleted'), c.reqId, null, c.role);
          save();
          return { status: 204, headers: { ETag: etagOf(rec) } };
        },

        restore(c) {
          const rec = find(c.params.id, true);
          if (!rec.deleted_at) throw new ApiError(409, 'not-deleted', `${cfg.label} is not withdrawn`, `Only a withdrawn ${cfg.label} can be restored.`);
          rec.deleted_at = null;
          rec.updated_at = iso();
          rec.version += 1;
          record(rec, ev('restored'), c.reqId, null, c.role);
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

    /* ── policies ── */

    const POLICY_WRITABLE = new Set(['holder', 'product', 'coverages', 'limit', 'deductible', 'coinsurance_pct', 'premium_annual', 'start_date', 'end_date', 'status', 'exclusions', 'waiting_period_days', 'auto_approve_limit']);
    const POLICY_READ_ONLY = new Set(['id', 'object', 'usage', 'version', 'created_at', 'updated_at', 'links']);

    function validatePolicy(input) {
      const errors = [];
      const chk = makeCheck(input, errors);
      if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
      chk.unknown(POLICY_WRITABLE, POLICY_READ_ONLY);
      const v = {};
      chk.str('holder', v, { min: 2, max: 60 });
      if (input.holder === undefined) chk.err('/holder', 'required', 'holder is required.');
      chk.enm('product', v, PRODUCTS);
      chk.list('coverages', v, CLAIM_TYPES, { min: 1, max: 8 });
      chk.num('limit', v, { min: 1000, max: 5000000, required: true });
      chk.num('deductible', v, { min: 0, max: 100000, def: 0 });
      chk.num('coinsurance_pct', v, { min: 0, max: 50, int: true, def: 0 });
      chk.num('premium_annual', v, { min: 50, max: 100000, required: true });
      chk.date('start_date', v, { required: true });
      chk.date('end_date', v, { required: true });
      chk.enm('status', v, POLICY_STATUSES, 'active');
      chk.list('exclusions', v, EXCLUSIONS, { max: 4 });
      chk.num('waiting_period_days', v, { min: 0, max: 180, int: true, def: 0 });
      chk.num('auto_approve_limit', v, { min: 0, max: 1000000, def: 0 });
      return { value: errors.length ? undefined : v, errors };
    }

    function policyRules(next, prev) {
      const errors = [];
      const err = (pointer, code, message) => errors.push({ pointer, code, message });
      if (!prev && next.status !== 'active') err('/status', 'invalid_initial_state', 'A new policy must start as "active".');
      const span = daysBetween(next.start_date, next.end_date);
      if (span <= 0) err('/end_date', 'invariant', 'end_date must be after start_date.');
      else if (span > 800) err('/end_date', 'invariant', 'A policy term cannot exceed 800 days.');
      next.coverages.forEach((cv, i) => { if (!PRODUCT_COVERAGES[next.product].includes(cv)) err(`/coverages/${i}`, 'invariant', `"${cv}" cannot be sold under a ${next.product} policy (allowed: ${PRODUCT_COVERAGES[next.product].join(', ')}).`); });
      if (next.deductible > next.limit) err('/deductible', 'invariant', 'The deductible cannot exceed the policy limit.');
      if (next.auto_approve_limit > next.limit) err('/auto_approve_limit', 'invariant', 'auto_approve_limit cannot exceed the policy limit.');
      if (prev) {
        const u = usageOf(prev);
        if (next.limit < money(u.paid + u.reserved)) err('/limit', 'invariant', `The limit cannot drop below the ${money(u.paid + u.reserved)} already paid or reserved.`);
      }
      return errors;
    }

    const policies = crud({
      key: 'policies', label: 'policy', base: '/v1/policies',
      view: (p) => ({ holder: p.holder, product: p.product, coverages: [...p.coverages], limit: p.limit, deductible: p.deductible, coinsurance_pct: p.coinsurance_pct, premium_annual: p.premium_annual, start_date: p.start_date, end_date: p.end_date, status: p.status, exclusions: [...p.exclusions], waiting_period_days: p.waiting_period_days, auto_approve_limit: p.auto_approve_limit }),
      present: presentPolicy, validate: validatePolicy, rules: policyRules,
      immutable: ['product', 'start_date'], transitions: POLICY_TRANSITIONS,
      build(v) { const t = iso(); return { id: newId('pol'), ...v, version: 1, created_at: t, updated_at: t, deleted_at: null }; },
      apply: (rec, next) => Object.assign(rec, next),
      list: {
        key: 'policies', base: '/v1/policies', present: presentPolicy,
        sortable: ['created_at', 'updated_at', 'premium_annual', 'limit', 'start_date'],
        fieldPaths: Object.keys(presentPolicy({ id: 'x', coverages: [], exclusions: [], limit: 0 })),
        valueOf: (r, k) => r[k],
        parse({ q, oneOf }) {
          const product = oneOf('product', PRODUCTS);
          const status = oneOf('status', POLICY_STATUSES);
          const text = (q.get('q') || '').trim().toLowerCase();
          return (r) => (!product || product.includes(r.product)) && (!status || status.includes(r.status)) && (!text || r.holder.toLowerCase().includes(text));
        },
      },
    });

    /* ── claims ── */

    const CLAIM_WRITABLE = new Set(['policy_id', 'type', 'incident_date', 'amount_claimed', 'description']);
    const CLAIM_READ_ONLY = new Set(['id', 'object', 'claim_number', 'status', 'assessment', 'approved_amount', 'paid_amount', 'paid_at', 'payment_reference', 'decision', 'documents', 'appeal_count', 'appeal_reason', 'filed_at', 'version', 'created_at', 'updated_at', 'deleted_at', 'links']);

    function validateClaim(input) {
      const errors = [];
      const chk = makeCheck(input, errors);
      if (!isObj(input)) return { errors: [{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }] };
      chk.unknown(CLAIM_WRITABLE, CLAIM_READ_ONLY);
      const v = {};
      chk.str('policy_id', v, { min: 4, max: 60, pattern: /^pol_\w+$/, patternMsg: 'policy_id must look like pol_…' });
      if (input.policy_id === undefined) chk.err('/policy_id', 'required', 'policy_id is required.');
      chk.enm('type', v, CLAIM_TYPES);
      chk.date('incident_date', v, { required: true });
      chk.num('amount_claimed', v, { min: 1, max: 10000000, required: true });
      chk.str('description', v, { min: 10, max: 1000 });
      if (input.description === undefined) chk.err('/description', 'required', 'description is required.');
      return { value: errors.length ? undefined : v, errors };
    }

    function claimRules(next, prev) {
      const errors = [];
      const err = (pointer, code, message) => errors.push({ pointer, code, message });
      if (!state.policies[next.policy_id]) err('/policy_id', 'unknown_policy', `No policy "${next.policy_id}" exists.`);
      const today = ymd(Date.now());
      if (next.incident_date > today) err('/incident_date', 'future_date', 'incident_date cannot be in the future.');
      else if (daysBetween(next.incident_date, today) > 1095) err('/incident_date', 'too_old', 'Incidents older than 3 years cannot be claimed.');
      return errors;
    }

    function buildClaim(value, o) {
      const policy = state.policies[value.policy_id];
      const others = liveClaims().filter((c) => c.policy_id === policy.id);
      const assessment = assessClaim(value, policy, others, o.now, committedOn(policy.id));
      const path = assessment.routing.path;
      const t = iso(o.now);
      const n = (state.counters.claim += 1);
      const rec = {
        id: newId('clm'), claim_number: `CLM-${new Date(o.now).getUTCFullYear()}-${String(n).padStart(6, '0')}`, ...value,
        status: { 'auto-denied': 'denied', siu: 'siu_review', adjuster: 'under_review', 'straight-through': 'approved' }[path],
        assessment, approved_amount: null, paid_amount: null, paid_at: null, payment_reference: null, decision: null,
        documents: [], appeal_count: 0, appeal_reason: null, filed_at: t, version: 1, created_at: t, updated_at: t, deleted_at: null,
      };
      if (path === 'straight-through') {
        rec.approved_amount = assessment.coverage.payable_estimate;
        rec.decision = { by: 'system', outcome: 'approve', reason: assessment.routing.reason, at: t };
      } else if (path === 'auto-denied') {
        rec.decision = { by: 'system', outcome: 'deny', reason: assessment.routing.reason, reason_codes: assessment.eligibility.filter((r) => r.hard && !r.passed).map((r) => r.rule), at: t };
      }
      return rec;
    }

    const claims = crud({
      key: 'claims', label: 'claim', base: '/v1/claims',
      view: (r) => ({ policy_id: r.policy_id, type: r.type, incident_date: r.incident_date, amount_claimed: r.amount_claimed, description: r.description }),
      present: presentClaim, validate: validateClaim, rules: claimRules,
      immutable: ['policy_id', 'type', 'incident_date'],
      events: { created: 'filed', deleted: 'withdrawn' }, noPurge: true,
      canEdit(rec) {
        if (!EDITABLE_CLAIM_STATES.includes(rec.status)) {
          throw new ApiError(409, 'claim-locked', 'Claim is locked', `A claim in "${rec.status}" can no longer be edited. Editing is allowed while it is ${EDITABLE_CLAIM_STATES.join(', ')}.`, { status: rec.status });
        }
      },
      canDelete(rec) {
        if (rec.status === 'paid') throw new ApiError(409, 'claim-paid', 'Claim already paid', 'A paid claim cannot be withdrawn.');
      },
      build: (v) => buildClaim(v, { now: Date.now() }),
      afterCreate(rec, c) {
        if (rec.decision && rec.decision.by === 'system') record(rec, 'auto-decision', c.reqId, { status: { from: null, to: rec.status } }, 'system');
      },
      apply(rec, next) {
        Object.assign(rec, { amount_claimed: next.amount_claimed, description: next.description });
        const policy = state.policies[rec.policy_id];
        const others = liveClaims().filter((x) => x.policy_id === policy.id && x.id !== rec.id);
        rec.assessment = assessClaim(view4(rec), policy, others, Date.parse(rec.filed_at), committedOn(policy.id, rec.id));
      },
      list: {
        key: 'claims', base: '/v1/claims', present: presentClaim,
        sortable: ['created_at', 'updated_at', 'amount_claimed', 'fraud_score', 'incident_date'],
        fieldPaths: Object.keys(presentClaim({ id: 'x', assessment: {}, documents: [] })),
        valueOf: (r, k) => (k === 'fraud_score' ? r.assessment.fraud.score : r[k]),
        parse({ q, num, bad, oneOf }) {
          const status = oneOf('status', CLAIM_STATUSES);
          const type = oneOf('type', CLAIM_TYPES);
          const risk = oneOf('risk', RISK_BANDS);
          const path = oneOf('path', ROUTING_PATHS);
          const policyId = (q.get('policy_id') || '').trim();
          const min = num('min_amount', { min: 0, max: 1e8 });
          const max = num('max_amount', { min: 0, max: 1e8 });
          const text = (q.get('q') || '').trim().toLowerCase();
          return (r) => {
            if (status && !status.includes(r.status)) return false;
            if (type && !type.includes(r.type)) return false;
            if (risk && !risk.includes(r.assessment.fraud.band)) return false;
            if (path && !path.includes(r.assessment.routing.path)) return false;
            if (policyId && r.policy_id !== policyId) return false;
            if (min !== undefined && r.amount_claimed < min) return false;
            if (max !== undefined && r.amount_claimed > max) return false;
            if (text && ![r.claim_number, r.description, r.policy_id].some((s) => String(s).toLowerCase().includes(text))) return false;
            return true;
          };
        },
      },
    });

    const view4 = (r) => ({ policy_id: r.policy_id, type: r.type, incident_date: r.incident_date, amount_claimed: r.amount_claimed, description: r.description });

    /** What would we pay right now if this claim were approved? */
    function payableNow(rec) {
      const policy = state.policies[rec.policy_id];
      const remaining = money(policy.limit - committedOn(policy.id, rec.id));
      const share = money(Math.max(0, rec.amount_claimed - policy.deductible) * (1 - policy.coinsurance_pct / 100));
      return { payable: money(Math.min(share, Math.max(0, remaining))), remaining };
    }

    function transition(rec, c, type, patch, changes) {
      Object.assign(rec, patch);
      rec.version += 1;
      rec.updated_at = iso();
      record(rec, type, c.reqId, changes, c.role);
      save();
      return { status: 200, headers: { ETag: etagOf(rec) }, body: presentClaim(rec) };
    }

    const actions = {
      decision(c) {
        const rec = claims.find(c.params.id);
        precondition(c.req, rec);
        const errors = [];
        const chk = makeCheck(isObj(c.body) ? c.body : {}, errors);
        if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }]);
        chk.unknown(new Set(['decision', 'approved_amount', 'reason']));
        const v = {};
        chk.enm('decision', v, Object.keys(DECISIONS));
        chk.num('approved_amount', v, { min: 0.01, max: 10000000 });
        chk.str('reason', v, { max: 500, def: '' });
        if (errors.length) throw validationError(errors);

        const d = DECISIONS[v.decision];
        if (!d.from.includes(rec.status)) {
          const allowed = Object.entries(DECISIONS).filter(([, x]) => x.from.includes(rec.status)).map(([k]) => k);
          throw new ApiError(409, 'illegal-transition', 'Decision not allowed in this state', `A claim in "${rec.status}" cannot be ${v.decision === 'approve' ? 'approved' : v.decision === 'deny' ? 'denied' : v.decision === 'escalate' ? 'escalated' : 'sent back for information'}.`,
            { from: rec.status, attempted: v.decision, allowed });
        }
        const reason = v.reason.trim();
        const need = (min, msg) => { if (reason.length < min) throw validationError([{ pointer: '/reason', code: 'invariant', message: msg }]); };
        const at = iso();
        const decision = { by: c.role, outcome: v.decision, reason, at };

        if (v.decision === 'approve') {
          const cap = payableNow(rec);
          const amount = v.approved_amount !== undefined ? v.approved_amount : cap.payable;
          if (cap.payable <= 0) throw validationError([{ pointer: '/approved_amount', code: 'nothing_payable', message: `Nothing is payable on this claim (remaining limit ${cap.remaining}, after deductible and coinsurance).` }]);
          if (amount > cap.payable) throw validationError([{ pointer: '/approved_amount', code: 'exceeds_payable', message: `Cannot approve ${amount}. The most payable is ${cap.payable} after deductible, coinsurance and the remaining limit.` }]);
          if (rec.assessment.routing.path === 'siu') need(20, 'Approving a claim that special investigations flagged needs a written justification of at least 20 characters.');
          if (rec.assessment.eligibility.some((r) => r.hard && !r.passed)) need(20, 'Approving a claim that failed hard eligibility rules is an override and needs a justification of at least 20 characters.');
          return transition(rec, c, 'decision', { status: 'approved', approved_amount: amount, decision }, { status: { from: rec.status, to: 'approved' }, approved_amount: { from: rec.approved_amount, to: amount } });
        }
        need(10, `A "${v.decision}" decision needs a reason of at least 10 characters.`);
        return transition(rec, c, 'decision', { status: d.to, approved_amount: null, decision }, { status: { from: rec.status, to: d.to } });
      },

      pay(c) {
        const idem = idempotency(c);
        if (idem.replay) return idem.replay;
        const rec = claims.find(c.params.id);
        precondition(c.req, rec);
        if (rec.status !== 'approved') {
          throw new ApiError(409, 'illegal-transition', rec.status === 'paid' ? 'Already paid' : 'Claim is not approved', rec.status === 'paid'
            ? `This claim was already paid on ${rec.paid_at} (reference ${rec.payment_reference}). Use an Idempotency-Key to make retries safe.`
            : `Only an approved claim can be paid; this one is "${rec.status}".`, { from: rec.status, allowed: rec.status === 'paid' ? [] : [] });
        }
        const res = transition(rec, c, 'paid', { status: 'paid', paid_amount: rec.approved_amount, paid_at: iso(), payment_reference: 'PAY-' + rand36(8).toUpperCase() },
          { status: { from: 'approved', to: 'paid' }, paid_amount: { from: null, to: rec.approved_amount } });
        remember(idem, res);
        save();
        return res;
      },

      appeal(c) {
        const rec = claims.find(c.params.id);
        if (c.req.headers['if-match'] !== undefined) precondition(c.req, rec);
        const errors = [];
        const chk = makeCheck(isObj(c.body) ? c.body : {}, errors);
        if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }]);
        chk.unknown(new Set(['reason']));
        const v = {};
        chk.str('reason', v, { min: 20, max: 1000 });
        if (c.body.reason === undefined) chk.err('/reason', 'required', 'reason is required.');
        if (errors.length) throw validationError(errors);
        if (rec.status !== 'denied') throw new ApiError(409, 'illegal-transition', 'Only denied claims can be appealed', `This claim is "${rec.status}".`, { from: rec.status });
        if (rec.appeal_count >= 1) throw new ApiError(409, 'appeal-limit', 'Appeal limit reached', 'A claim can be appealed only once.');
        const sinceDecision = daysBetween(ymd(Date.parse(rec.decision ? rec.decision.at : rec.updated_at)), ymd(Date.now()));
        if (sinceDecision > APPEAL_WINDOW_DAYS) throw new ApiError(409, 'appeal-window-closed', 'Appeal window closed', `Appeals must be lodged within ${APPEAL_WINDOW_DAYS} days of the decision (this was ${sinceDecision} days ago).`);
        return transition(rec, c, 'appealed', { status: 'appealed', appeal_count: rec.appeal_count + 1, appeal_reason: v.reason }, { status: { from: 'denied', to: 'appealed' } });
      },

      documents(c) {
        const rec = claims.find(c.params.id);
        const errors = [];
        const chk = makeCheck(isObj(c.body) ? c.body : {}, errors);
        if (!isObj(c.body)) throw validationError([{ pointer: '', code: 'type', message: 'Body must be a JSON object.' }]);
        chk.unknown(new Set(['kind', 'name']));
        const v = {};
        chk.enm('kind', v, DOC_KINDS);
        chk.str('name', v, { min: 2, max: 80 });
        if (c.body.name === undefined) chk.err('/name', 'required', 'name is required.');
        if (errors.length) throw validationError(errors);
        if (!['under_review', 'info_requested', 'siu_review', 'appealed', 'approved'].includes(rec.status)) throw new ApiError(409, 'claim-locked', 'Claim is locked', `Documents cannot be added to a claim in "${rec.status}".`, { status: rec.status });
        if (rec.documents.length >= 10) throw new ApiError(409, 'document-limit', 'Document limit reached', 'A claim can hold at most 10 documents.');
        const doc = { id: 'doc_' + rand36(6), kind: v.kind, name: v.name, added_by: c.role, added_at: iso() };
        const patch = { documents: [...rec.documents, doc] };
        const resumed = rec.status === 'info_requested';
        if (resumed) patch.status = 'under_review';
        return transition(rec, c, 'document-added', patch, { documents: { from: rec.documents.length, to: rec.documents.length + 1 }, ...(resumed ? { status: { from: 'info_requested', to: 'under_review' } } : {}) });
      },
    };

    /* ── stats ── */

    function stats() {
      const live = liveClaims();
      const tally = (arr, fn) => arr.reduce((o, x) => { const k = fn(x); o[k] = (o[k] || 0) + 1; return o; }, {});
      const sum = (arr, fn) => money(arr.reduce((a, x) => a + (fn(x) || 0), 0));
      const payout = (c) => (c.status === 'paid' ? c.paid_amount : c.status === 'approved' ? c.approved_amount : 0);
      const byPath = tally(live, (c) => c.assessment.routing.path);
      const pols = Object.values(state.policies);
      const products = {};
      for (const p of PRODUCTS) {
        const premium = sum(pols.filter((x) => x.product === p && x.status === 'active'), (x) => x.premium_annual);
        const incurred = sum(live.filter((c) => state.policies[c.policy_id] && state.policies[c.policy_id].product === p), payout);
        products[p] = { premium_written: premium, incurred, loss_ratio: premium ? money(incurred / premium) : null };
      }
      const frac = (n) => (live.length ? money(n / live.length) : 0);
      return {
        status: 200,
        body: {
          claims: {
            total: live.length,
            by_status: { ...Object.fromEntries(CLAIM_STATUSES.map((s) => [s, 0])), ...tally(live, (c) => c.status) },
            by_path: { ...Object.fromEntries(ROUTING_PATHS.map((s) => [s, 0])), ...byPath },
            straight_through_rate: frac(byPath['straight-through'] || 0),
            flagged_rate: frac(live.filter((c) => c.assessment.fraud.band === 'high').length),
            mean_fraud_score: live.length ? money(live.reduce((a, c) => a + c.assessment.fraud.score, 0) / live.length) : 0,
          },
          money: { claimed: sum(live, (c) => c.amount_claimed), approved: sum(live.filter((c) => c.status === 'approved' || c.status === 'paid'), (c) => (c.status === 'paid' ? c.paid_amount : c.approved_amount)), paid: sum(live.filter((c) => c.status === 'paid'), (c) => c.paid_amount) },
          products,
        },
      };
    }

    /* ── seed data ── */

    function seed() {
      const now = Date.now();
      state = { v: 1, policies: {}, claims: {}, history: {}, idem: {}, counters: { claim: 0 } };
      const day = (n) => ymd(now + n * DAY);
      const PS = [
        { id: 'pol_auto_ada', holder: 'Ada Okoye', product: 'auto', coverages: ['collision', 'theft', 'fire', 'glass', 'liability'], limit: 20000, deductible: 500, coinsurance_pct: 0, premium_annual: 1200, start_date: day(-240), end_date: day(125), status: 'active', exclusions: ['racing', 'intentional-damage'], waiting_period_days: 0, auto_approve_limit: 1500 },
        { id: 'pol_auto_lapsed', holder: 'Bayo Adeyemi', product: 'auto', coverages: ['collision', 'theft', 'glass'], limit: 15000, deductible: 500, coinsurance_pct: 0, premium_annual: 980, start_date: day(-300), end_date: day(65), status: 'lapsed', exclusions: ['racing'], waiting_period_days: 0, auto_approve_limit: 1500 },
        { id: 'pol_home_chidi', holder: 'Chidi Nwosu', product: 'home', coverages: ['fire', 'water', 'theft', 'storm'], limit: 150000, deductible: 1000, coinsurance_pct: 0, premium_annual: 900, start_date: day(-330), end_date: day(35), status: 'active', exclusions: ['flood', 'war'], waiting_period_days: 0, auto_approve_limit: 2000 },
        { id: 'pol_health_ngozi', holder: 'Ngozi Eze', product: 'health', coverages: ['medical', 'dental'], limit: 30000, deductible: 250, coinsurance_pct: 20, premium_annual: 1800, start_date: day(-200), end_date: day(165), status: 'active', exclusions: [], waiting_period_days: 30, auto_approve_limit: 1000 },
        { id: 'pol_health_new', holder: 'Emeka Obi', product: 'health', coverages: ['medical', 'dental'], limit: 30000, deductible: 250, coinsurance_pct: 20, premium_annual: 1800, start_date: day(-12), end_date: day(353), status: 'active', exclusions: [], waiting_period_days: 30, auto_approve_limit: 1000 },
        { id: 'pol_travel_tunde', holder: 'Tunde Bello', product: 'travel', coverages: ['trip-cancellation', 'baggage', 'medical'], limit: 5000, deductible: 100, coinsurance_pct: 0, premium_annual: 120, start_date: day(-5), end_date: day(20), status: 'active', exclusions: ['war'], waiting_period_days: 0, auto_approve_limit: 800 },
      ];
      PS.forEach((p) => {
        const t = iso(now - 300 * DAY);
        state.policies[p.id] = { ...p, version: 1, created_at: t, updated_at: t, deleted_at: null };
        state.history[p.id] = [{ seq: 1, type: 'created', at: t, version: 1, actor: 'seed', request_id: 'req_seed', changes: null }];
      });

      const file = (input, filedDaysAgo) => {
        const rec = buildClaim(input, { now: now - filedDaysAgo * DAY });
        state.claims[rec.id] = rec;
        record(rec, 'filed', 'req_seed', null, 'claimant');
        if (rec.decision) record(rec, 'auto-decision', 'req_seed', { status: { from: null, to: rec.status } }, 'system');
        return rec;
      };
      const settle = (rec, patch, type, daysAgo, changes) => {
        Object.assign(rec, patch);
        rec.version += 1;
        rec.updated_at = iso(now - daysAgo * DAY);
        record(rec, type, 'req_seed', changes, 'adjuster');
      };
      const dec = (outcome, reason, daysAgo) => ({ by: 'adjuster', outcome, reason, at: iso(now - daysAgo * DAY) });

      const A = file({ policy_id: 'pol_auto_ada', type: 'collision', incident_date: day(-20), amount_claimed: 2400, description: 'Rear-ended at a traffic light on Allen Avenue. Police report filed and photos taken.' }, 19);
      settle(A, { status: 'info_requested', decision: dec('request_info', 'Please upload the police report and a repair estimate.', 18) }, 'decision', 18, { status: { from: 'under_review', to: 'info_requested' } });

      const B = file({ policy_id: 'pol_auto_ada', type: 'glass', incident_date: day(-12), amount_claimed: 950, description: 'A rock hit the windshield on the highway and cracked it.' }, 11);
      settle(B, { status: 'paid', paid_amount: B.approved_amount, paid_at: iso(now - 10 * DAY), payment_reference: 'PAY-SEED0001' }, 'paid', 10, { status: { from: 'approved', to: 'paid' } });

      const C = file({ policy_id: 'pol_home_chidi', type: 'water', incident_date: day(-90), amount_claimed: 3200, description: 'A pipe burst under the kitchen sink and soaked the floor and cabinets.' }, 88);
      settle(C, { status: 'approved', approved_amount: 2200, decision: dec('approve', 'Plumber invoice verified.', 85) }, 'decision', 85, { status: { from: 'under_review', to: 'approved' } });
      settle(C, { status: 'paid', paid_amount: 2200, paid_at: iso(now - 80 * DAY), payment_reference: 'PAY-SEED0002' }, 'paid', 80, { status: { from: 'approved', to: 'paid' } });

      file({ policy_id: 'pol_home_chidi', type: 'water', incident_date: day(-89), amount_claimed: 3300, description: 'Water damage in the kitchen after the pipe burst, urgent settlement needed for the ruined cabinets.' }, 77);
      file({ policy_id: 'pol_health_new', type: 'medical', incident_date: day(-5), amount_claimed: 1200, description: 'Emergency room visit after a fall at home.' }, 4);
      file({ policy_id: 'pol_auto_ada', type: 'theft', incident_date: day(-8), amount_claimed: 18500, description: 'Car stolen overnight, total loss, no police report yet, need cash urgently.' }, 7);
      file({ policy_id: 'pol_travel_tunde', type: 'baggage', incident_date: day(-2), amount_claimed: 650, description: 'Suitcase never arrived on the connecting flight.' }, 1);
      file({ policy_id: 'pol_auto_lapsed', type: 'collision', incident_date: day(-15), amount_claimed: 1800, description: 'Minor collision in a parking lot.' }, 14);
      file({ policy_id: 'pol_health_ngozi', type: 'dental', incident_date: day(-6), amount_claimed: 600, description: 'Root canal treatment at the dental clinic.' }, 5);
      save();
    }

    if (needsSeed) seed();

    /* ── routing ── */

    const handlers = {
      index() {
        return {
          status: 200,
          body: {
            name: 'Roodie Insuretech API', version: API_VERSION, sandbox: true,
            description: 'Insurance claims intake, coverage maths, transparent fraud scoring, adjuster decisions, payouts and appeals.',
            auth: { scheme: 'Bearer', roles: { claimant: 'Bearer claimant_demo_key (file, edit, withdraw, appeal, add documents)', adjuster: 'Bearer adjuster_demo_key (decide, pay, restore, manage policies)' }, note: 'Reads are open in the sandbox.' },
            workflow: ['POST /claims files a claim and triages it into straight-through, adjuster, siu or auto-denied.', 'POST /claims/{id}/decision (adjuster): approve, deny, request_info, escalate.', 'POST /claims/{id}/pay (adjuster, use Idempotency-Key) pays an approved claim.', 'POST /claims/{id}/appeal (claimant) re-opens a denied claim once, within 30 days.'],
            conventions: ['Every claim carries its full assessment: eligibility rules, coverage maths, fraud flags and the routing reason.', 'Errors are RFC 9457 application/problem+json.', 'Decisions, payments and edits require If-Match (ETag optimistic concurrency).', 'POST /claims and POST /claims/{id}/pay honour Idempotency-Key for 24h.', 'Withdrawing a claim is a soft delete; claims are never permanently deleted.', 'Lists use opaque keyset cursors.'],
            rate_limit: { capacity: RATE_CAPACITY, refill_per_second: RATE_REFILL_PER_SEC },
            links: { policies: '/v1/policies', claims: '/v1/claims', stats: '/v1/stats' },
          },
        };
      },
      'p.list': policies.list, 'p.create': policies.create, 'p.read': policies.read, 'p.replace': policies.replace, 'p.patch': policies.patch, 'p.history': policies.history,
      'c.list': claims.list, 'c.create': claims.create, 'c.read': claims.read, 'c.patch': claims.patch, 'c.remove': claims.remove, 'c.restore': claims.restore, 'c.history': claims.history,
      decision: actions.decision, pay: actions.pay, appeal: actions.appeal, documents: actions.documents,
      stats,
      reset() { seed(); return { status: 200, body: { reset: true, policies: Object.keys(state.policies).length, claims: Object.keys(state.claims).length } }; },
    };

    const ROUTES = [
      ['GET', '/v1', 'index'],
      ['GET', '/v1/policies', 'p.list'],
      ['POST', '/v1/policies', 'p.create', 'json', 'adjuster'],
      ['GET', '/v1/policies/:id', 'p.read'],
      ['PUT', '/v1/policies/:id', 'p.replace', 'json', 'adjuster'],
      ['PATCH', '/v1/policies/:id', 'p.patch', 'patch', 'adjuster'],
      ['GET', '/v1/policies/:id/history', 'p.history'],
      ['GET', '/v1/claims', 'c.list'],
      ['POST', '/v1/claims', 'c.create', 'json', 'claimant'],
      ['GET', '/v1/claims/:id', 'c.read'],
      ['PATCH', '/v1/claims/:id', 'c.patch', 'patch', 'claimant'],
      ['DELETE', '/v1/claims/:id', 'c.remove', null, 'claimant'],
      ['POST', '/v1/claims/:id/restore', 'c.restore', null, 'adjuster'],
      ['GET', '/v1/claims/:id/history', 'c.history'],
      ['POST', '/v1/claims/:id/decision', 'decision', 'json', 'adjuster'],
      ['POST', '/v1/claims/:id/pay', 'pay', null, 'adjuster'],
      ['POST', '/v1/claims/:id/appeal', 'appeal', 'json', 'claimant'],
      ['POST', '/v1/claims/:id/documents', 'documents', 'json', 'claimant'],
      ['GET', '/v1/stats', 'stats'],
      ['POST', '/v1/sandbox/reset', 'reset', null, 'adjuster'],
    ].map(([method, pattern, fn, body, role]) => ({
      method, fn, body, role,
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

    function authenticate(req, need) {
      const h = req.headers.authorization || '';
      const m = /^Bearer\s+(.+)$/i.exec(h);
      if (!m) throw new ApiError(401, 'unauthorized', 'Authentication required', 'Send "Authorization: Bearer claimant_demo_key" (or adjuster_demo_key for adjuster actions).', { headers: { 'WWW-Authenticate': 'Bearer realm="roodie-insuretech"' } });
      const role = TOKENS[m[1]];
      if (!role) throw new ApiError(401, 'invalid-token', 'Invalid token', 'The bearer token was not recognised.', { headers: { 'WWW-Authenticate': 'Bearer realm="roodie-insuretech", error="invalid_token"' } });
      if (ROLE_RANK[role] < ROLE_RANK[need]) throw new ApiError(403, 'forbidden', 'Insufficient role', `This action needs the "${need}" role; your token is a "${role}".`, { required_role: need, your_role: role });
      return role;
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
      const role = hit.r.role ? authenticate(req, hit.r.role) : null;
      const body = hit.r.body ? parseBody(req, hit.r.body) : undefined;
      return handlers[hit.r.fn]({ req, params: hit.m.groups || {}, query: req.query, body, reqId, role: role || 'anonymous' });
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
      if (!(e instanceof ApiError)) e = new ApiError(500, 'internal-error', 'Internal error', 'Something went wrong inside the Insuretech engine. This one is on us.');
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
        if (!(e instanceof ApiError)) console.error('[claims-api]', e);
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
      peekClaims() { return Object.values(state.claims).sort(byCreated).map((r) => ({ ...presentClaim(r), etag: etagOf(r) })); },
      peekPolicies() { return Object.values(state.policies).sort(byCreated).map((r) => ({ ...presentPolicy(r), etag: etagOf(r) })); },
      reset() { seed(); },
    };
  }

  return {
    version: API_VERSION,
    base: BASE,
    tokens: { claimant: 'claimant_demo_key', adjuster: 'adjuster_demo_key' },
    createService,
    service: null, // populated below in browsers
  };
});

if (typeof window !== 'undefined' && window.ClaimsAPI && !window.ClaimsAPI.service) {
  window.ClaimsAPI.service = window.ClaimsAPI.createService();
  window.claims = window.ClaimsAPI.service; // `claims.fetch('/v1/claims')` from the devtools console
}
