/* Claims API console: the interactive test bench for claims-api.js (loaded after it). */
(function () {
  const $ = (s) => document.querySelector(s);
  const api = window.claims;
  const noteEl = $("#claims-status");
  if (!api) { if (noteEl) noteEl.textContent = "The Roodie Insuretech API engine failed to load (claims-api.js)."; return; }

  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const j = (o) => JSON.stringify(o, null, 2);
  const usd = (n) => (n === null || n === undefined ? "—" : "$" + Number(n).toLocaleString(undefined, { minimumFractionDigits: Number(n) % 1 ? 2 : 0, maximumFractionDigits: 2 }));
  const T = ClaimsAPI.tokens;
  const AUTH_C = "Authorization: Bearer " + T.claimant;
  const AUTH_A = "Authorization: Bearer " + T.adjuster;
  const MERGE = "Content-Type: application/merge-patch+json";
  const ctx = { claimId: "", claimEtag: "", policyId: "", cursor: "", idem: "demo-" + Math.random().toString(36).slice(2, 10) };
  let last = null, tab = "body", booted = false;
  const seen = new Map();
  const logItems = [];
  const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

  /* ── request recipes ── */
  const filing = (o) => j({ policy_id: "pol_auto_ada", type: "collision", incident_date: day(-3), amount_claimed: 2600, description: "Hit a pothole and bent the front wheel and suspension.", ...o });

  const RECIPES = [
    { group: "File a claim", items: [
      { label: "Small glass claim", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({ type: "glass", amount_claimed: 900, incident_date: day(-1), description: "A stone chipped the windshield on the motorway." }) },
      { label: "Needs an adjuster", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({}) },
      { label: "Fraud red flags", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({ type: "theft", amount_claimed: 19000, incident_date: day(-2), description: "Car stolen overnight, total loss, no police report, need cash urgently." }) },
      { label: "Lapsed policy", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({ policy_id: "pol_auto_lapsed", amount_claimed: 1200, description: "Scraped the side of the car on a gate post." }) },
      { label: "Inside waiting period", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({ policy_id: "pol_health_new", type: "medical", amount_claimed: 900, incident_date: day(-4), description: "Clinic visit and medication for a sudden fever." }) },
      { label: "Over the limit", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: filing({ policy_id: "pol_travel_tunde", type: "medical", amount_claimed: 9000, incident_date: day(-1), description: "Hospital treatment abroad after a cycling accident." }) },
      { label: "Retry-safe filing", method: "POST", path: "/v1/claims", headers: [AUTH_C, "Idempotency-Key: {{idem}}"], body: filing({ type: "storm", policy_id: "pol_home_chidi", amount_claimed: 1750, description: "Storm winds tore several tiles off the roof." }) }
    ] },
    { group: "Review", items: [
      { label: "List claims", method: "GET", path: "/v1/claims" },
      { label: "High fraud risk", method: "GET", path: "/v1/claims?risk=high&sort=-fraud_score&fields=claim_number,status,amount_claimed,assessment" },
      { label: "Straight-through only", method: "GET", path: "/v1/claims?path=straight-through" },
      { label: "Page 1 (limit 3)", method: "GET", path: "/v1/claims?limit=3&sort=-amount_claimed" },
      { label: "Next page", method: "GET", path: "/v1/claims?limit=3&sort=-amount_claimed&cursor={{cursor}}" },
      { label: "Get one", method: "GET", path: "/v1/claims/{{claim}}" },
      { label: "Conditional GET → 304", method: "GET", path: "/v1/claims/{{claim}}", headers: ["If-None-Match: {{etag}}"] },
      { label: "Audit trail", method: "GET", path: "/v1/claims/{{claim}}/history" }
    ] },
    { group: "Adjuster", items: [
      { label: "Approve", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, "If-Match: {{etag:under_review}}"], body: j({ decision: "approve", reason: "Repair estimate checked against the photos." }) },
      { label: "Deny", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, "If-Match: {{etag:under_review}}"], body: j({ decision: "deny", reason: "Damage is not consistent with the reported incident." }) },
      { label: "Request documents", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, "If-Match: {{etag:under_review}}"], body: j({ decision: "request_info", reason: "Please send the repair estimate and photos." }) },
      { label: "Escalate to SIU", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, "If-Match: {{etag:under_review}}"], body: j({ decision: "escalate", reason: "Wording in the report needs investigating." }) },
      { label: "Pay (idempotent)", method: "POST", path: "/v1/claims/{{claim:approved}}/pay", headers: [AUTH_A, "If-Match: {{etag:approved}}", "Idempotency-Key: pay-{{idem}}"] },
      { label: "Restore withdrawn", method: "POST", path: "/v1/claims/{{claim}}/restore", headers: [AUTH_A] }
    ] },
    { group: "Claimant", items: [
      { label: "Add a document", method: "POST", path: "/v1/claims/{{claim:info_requested}}/documents", headers: [AUTH_C], body: j({ kind: "repair-estimate", name: "garage-estimate.pdf" }) },
      { label: "Edit amount", method: "PATCH", path: "/v1/claims/{{claim:under_review}}", headers: [AUTH_C, "If-Match: {{etag:under_review}}", MERGE], body: j({ amount_claimed: 1800 }) },
      { label: "Appeal a denial", method: "POST", path: "/v1/claims/{{claim:denied}}/appeal", headers: [AUTH_C], body: j({ reason: "The policy was active at the time and I have the receipts to prove the loss." }) },
      { label: "Withdraw", method: "DELETE", path: "/v1/claims/{{claim:under_review}}", headers: [AUTH_C, "If-Match: {{etag:under_review}}"] }
    ] },
    { group: "Policies + KPIs", items: [
      { label: "Policies", method: "GET", path: "/v1/policies" },
      { label: "One policy", method: "GET", path: "/v1/policies/{{policy}}" },
      { label: "Issue a policy", method: "POST", path: "/v1/policies", headers: [AUTH_A], body: j({ holder: "Zainab Musa", product: "auto", coverages: ["collision", "glass"], limit: 10000, deductible: 250, premium_annual: 700, start_date: day(-10), end_date: day(355), auto_approve_limit: 1000 }) },
      { label: "Raise a deductible", method: "PATCH", path: "/v1/policies/{{policy}}", headers: [AUTH_A, "If-Match: *", MERGE], body: j({ deductible: 750 }) },
      { label: "Stats + loss ratio", method: "GET", path: "/v1/stats" }
    ] },
    { group: "Scenarios", sim: true, items: [
      { label: "Full lifecycle", sim: "lifecycle" },
      { label: "Two adjusters collide", sim: "collide" },
      { label: "Double-pay attempt", sim: "double" },
      { label: "Duplicate claim", sim: "duplicate" }
    ] },
    { group: "Break it", bad: true, items: [
      { label: "422 bad claim", method: "POST", path: "/v1/claims", headers: [AUTH_C], body: j({ policy_id: "pol_nope", type: "meteor", incident_date: "2026-02-31", amount_claimed: -5, description: "short", status: "approved" }) },
      { label: "401 no token", method: "POST", path: "/v1/claims", headers: [], body: filing({}) },
      { label: "403 claimant deciding", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_C, "If-Match: *"], body: j({ decision: "approve" }) },
      { label: "428 no If-Match", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A], body: j({ decision: "approve" }) },
      { label: "412 stale ETag", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, 'If-Match: "1-deadbeef"'], body: j({ decision: "approve" }) },
      { label: "422 over-approve", method: "POST", path: "/v1/claims/{{claim:under_review}}/decision", headers: [AUTH_A, "If-Match: *"], body: j({ decision: "approve", approved_amount: 999999 }) },
      { label: "409 pay twice", method: "POST", path: "/v1/claims/{{claim:paid}}/pay", headers: [AUTH_A, "If-Match: *"] },
      { label: "409 edit a paid claim", method: "PATCH", path: "/v1/claims/{{claim:paid}}", headers: [AUTH_C, "If-Match: *", MERGE], body: j({ amount_claimed: 1 }) },
      { label: "422 change the policy", method: "PATCH", path: "/v1/claims/{{claim:under_review}}", headers: [AUTH_C, "If-Match: *", MERGE], body: j({ policy_id: "pol_home_chidi" }) },
      { label: "409 purge a claim", method: "DELETE", path: "/v1/claims/{{claim}}?purge=true", headers: [AUTH_C, "If-Match: *"] }
    ] }
  ];

  /* ── scripted scenarios: real API calls, narrated ── */
  const H = (role, extra) => ({ Authorization: "Bearer " + T[role], "Content-Type": "application/json", ...(extra || {}) });

  async function call(label, path, init, timeline) {
    const res = await api.fetch(path, init);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { /* no body */ }
    const summary = !data ? "" : data.object === "policy" ? data.id + " · limit " + usd(data.limit) : data.object === "claim"
      ? data.status + (data.payment_reference ? " · " + data.payment_reference : "") + (data.assessment && data.assessment.fraud ? " · fraud " + data.assessment.fraud.score : "")
      : data.title ? data.title + (data.detail ? ": " + data.detail.slice(0, 80) : "") : "";
    timeline.push(String(timeline.length + 1).padStart(2, "0") + "  " + label.padEnd(34) + res.status + "  " + summary + (res.headers.get("idempotent-replayed") ? "  (replayed)" : ""));
    absorb(res, text, path);
    return { res, data, etag: res.headers.get("etag") };
  }

  /** Each scenario gets its own brand-new policy, so earlier clicks can't trip duplicate or frequency flags. */
  async function freshPolicy(tl) {
    const r = await call("adjuster issues a clean policy", "/v1/policies", { method: "POST", headers: H("adjuster"), body: JSON.stringify({ holder: "Scenario " + Math.random().toString(36).slice(2, 6).toUpperCase(), product: "auto", coverages: ["collision", "theft", "glass"], limit: 20000, deductible: 500, premium_annual: 1100, start_date: day(-120), end_date: day(245), auto_approve_limit: 1500 }) }, tl);
    return r.data.id;
  }

  const SCENARIOS = {
    lifecycle: { title: "Full lifecycle: file, document, approve, pay, retry safely", async run(tl) {
      const pid = await freshPolicy(tl);
      const f = await call("claimant files a claim", "/v1/claims", { method: "POST", headers: H("claimant"), body: filing({ policy_id: pid, amount_claimed: 2600 }) }, tl);
      const id = f.data.id; let etag = f.etag;
      const d = await call("claimant adds a document", "/v1/claims/" + id + "/documents", { method: "POST", headers: H("claimant"), body: JSON.stringify({ kind: "photo", name: "damage-photo.jpg" }) }, tl); etag = d.etag;
      const a = await call("adjuster approves", "/v1/claims/" + id + "/decision", { method: "POST", headers: H("adjuster", { "If-Match": etag }), body: JSON.stringify({ decision: "approve", reason: "Photos match the estimate." }) }, tl); etag = a.etag;
      const key = "life-" + Math.random().toString(36).slice(2, 8);
      const p = await call("adjuster pays (Idempotency-Key)", "/v1/claims/" + id + "/pay", { method: "POST", headers: H("adjuster", { "If-Match": etag, "Idempotency-Key": key }) }, tl);
      await call("network retry, same key", "/v1/claims/" + id + "/pay", { method: "POST", headers: H("adjuster", { "If-Match": etag, "Idempotency-Key": key }) }, tl);
      await call("impatient click, no key", "/v1/claims/" + id + "/pay", { method: "POST", headers: H("adjuster", { "If-Match": "*" }) }, tl);
      return { verdict: "Paid once. The retry replayed the original response and the keyless duplicate was refused.", id, reference: p.data && p.data.payment_reference };
    } },
    collide: { title: "Two adjusters open the same claim; the second one is stopped", async run(tl) {
      const pid = await freshPolicy(tl);
      const f = await call("claimant files a claim", "/v1/claims", { method: "POST", headers: H("claimant"), body: filing({ policy_id: pid, amount_claimed: 2200 }) }, tl);
      const id = f.data.id; const shared = f.etag;
      const a = await call("adjuster A approves (ETag v1)", "/v1/claims/" + id + "/decision", { method: "POST", headers: H("adjuster", { "If-Match": shared }), body: JSON.stringify({ decision: "approve", reason: "Looks genuine." }) }, tl);
      await call("adjuster B denies (stale ETag v1)", "/v1/claims/" + id + "/decision", { method: "POST", headers: H("adjuster", { "If-Match": shared }), body: JSON.stringify({ decision: "deny", reason: "Looks suspicious to me." }) }, tl);
      await call("adjuster B re-reads, tries again", "/v1/claims/" + id + "/decision", { method: "POST", headers: H("adjuster", { "If-Match": a.etag }), body: JSON.stringify({ decision: "deny", reason: "Looks suspicious to me." }) }, tl);
      return { verdict: "B's stale write got 412, and the retry got 409 because an approved claim cannot be denied. Nobody silently overwrote anybody.", id };
    } },
    double: { title: "Double-pay attempt: a payout must never happen twice", async run(tl) {
      const pid = await freshPolicy(tl);
      const f = await call("claimant files a claim", "/v1/claims", { method: "POST", headers: H("claimant"), body: filing({ policy_id: pid, amount_claimed: 2000 }) }, tl);
      const id = f.data.id;
      const a = await call("adjuster approves", "/v1/claims/" + id + "/decision", { method: "POST", headers: H("adjuster", { "If-Match": f.etag }), body: JSON.stringify({ decision: "approve", reason: "Estimate verified." }) }, tl);
      const key = "dbl-" + Math.random().toString(36).slice(2, 8);
      const init = { method: "POST", headers: H("adjuster", { "If-Match": a.etag, "Idempotency-Key": key }) };
      const results = await Promise.all([api.fetch("/v1/claims/" + id + "/pay", init), api.fetch("/v1/claims/" + id + "/pay", init), api.fetch("/v1/claims/" + id + "/pay", init)]);
      const bodies = await Promise.all(results.map((r) => r.json()));
      tl.push(String(tl.length + 1).padStart(2, "0") + "  3 simultaneous pay requests         " + results.map((r) => r.status).join(" / ") + "  refs: " + [...new Set(bodies.map((b) => b.payment_reference))].join(", "));
      const check = await call("read the claim back", "/v1/claims/" + id, {}, tl);
      return { verdict: "Three simultaneous requests produced exactly one payment reference. paid_amount is " + usd(check.data.paid_amount) + ".", id };
    } },
    duplicate: { title: "Duplicate claim: the same loss reported twice", async run(tl) {
      const pid = await freshPolicy(tl);
      const body = filing({ policy_id: pid, type: "collision", amount_claimed: 1850, incident_date: day(-4), description: "Side-swiped by a delivery van while parked on Allen Avenue." });
      const first = await call("claimant files the claim", "/v1/claims", { method: "POST", headers: H("claimant", { "Idempotency-Key": "dup-a-" + ctx.idem }), body }, tl);
      const second = await call("files it again (new key)", "/v1/claims", { method: "POST", headers: H("claimant", { "Idempotency-Key": "dup-b-" + ctx.idem }), body }, tl);
      await call("retries the second (same key)", "/v1/claims", { method: "POST", headers: H("claimant", { "Idempotency-Key": "dup-b-" + ctx.idem }), body }, tl);
      const flags = second.data && second.data.assessment ? second.data.assessment.fraud.flags.map((f) => f.code) : [];
      return { verdict: "The retry was replayed (no third claim), but the second filing was flagged as: " + (flags.join(", ") || "none") + ".", first_claim: first.data.claim_number, second_claim: second.data.claim_number, id: second.data.id };
    } }
  };

  /* ── helpers ── */
  const byStatus = (status) => api.peekClaims().find((c) => !c.deleted_at && c.status === status);
  function fill(text) {
    return String(text)
      .replace(/\{\{claim:(\w+)\}\}/g, (m, s) => { const c = byStatus(s); return c ? c.id : ctx.claimId || "clm_unknown"; })
      .replace(/\{\{etag:(\w+)\}\}/g, (m, s) => { const c = byStatus(s); return c ? c.etag : "*"; })
      .replace(/\{\{claim\}\}/g, ctx.claimId || "clm_unknown")
      .replace(/\{\{etag\}\}/g, ctx.claimEtag || "*")
      .replace(/\{\{policy\}\}/g, ctx.policyId || "pol_auto_ada")
      .replace(/\{\{cursor\}\}/g, ctx.cursor)
      .replace(/\{\{idem\}\}/g, ctx.idem);
  }

  function highlight(json) {
    return json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g, (m, s, colon, kw) => {
      if (s) return colon ? '<span class="j-key">' + s + "</span>" + colon : '<span class="j-str">' + s + "</span>";
      if (kw) return '<span class="j-kw">' + m + "</span>";
      return '<span class="j-num">' + m + "</span>";
    });
  }

  function parseHeaders(text) {
    const out = {};
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const i = line.indexOf(":");
      if (i < 1) throw new Error('Bad header line: "' + line + '"');
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return out;
  }

  const el = { method: $("#cl-method"), path: $("#cl-path"), headers: $("#cl-headers"), body: $("#cl-body"), send: $("#cl-send") };

  function load(r) {
    el.method.value = r.method;
    el.path.value = fill(r.path);
    el.headers.value = (r.headers || []).map(fill).join("\n");
    el.body.value = r.body ? fill(r.body) : "";
  }

  function renderVars() {
    const v = (k, val) => "<span><b>" + k + "</b> <span>" + esc(val || "—") + "</span></span>";
    $("#cl-vars").innerHTML = v("{{claim}}", ctx.claimId) + v("{{etag}}", ctx.claimEtag) + v("{{policy}}", ctx.policyId) + v("{{cursor}}", ctx.cursor ? ctx.cursor.slice(0, 12) + "…" : "");
  }

  function renderRecipes() {
    const root = $("#cl-recipes");
    root.innerHTML = "";
    RECIPES.forEach((g) => {
      const row = document.createElement("div");
      row.className = "recipe-group";
      row.innerHTML = "<span>" + g.group + "</span>";
      g.items.forEach((r) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "chip" + (g.bad ? " bad" : "") + (g.sim ? " sim" : "");
        b.textContent = r.label;
        b.addEventListener("click", () => {
          if (r.sim) return scenario(r.sim);
          load(r);
          if (r.method === "GET") send(); else el.send.focus();
        });
        row.appendChild(b);
      });
      root.appendChild(row);
    });
    const hint = document.createElement("p");
    hint.className = "recipe-hint";
    hint.innerHTML = "Two roles: <b>claimant</b> files, edits, appeals and withdraws; <b>adjuster</b> decides, pays and restores. Each recipe carries the right token. Reads fire instantly; writes load into the form first. <code>{{claim:under_review}}</code>-style placeholders pick a claim in the right state, so Approve → Pay works in order. Click any row below to see <em>why</em> the engine routed a claim the way it did.";
    root.appendChild(hint);
  }

  /* ── response rendering ── */
  function renderResponse() {
    if (!last) return;
    const r = last;
    $("#cl-res-status").innerHTML = '<span class="pill s' + String(r.status)[0] + '">' + r.status + " " + esc(r.statusText) + '</span><span class="meta">' + r.ms + " ms · " + r.size + " B</span>" + (r.note ? '<span class="meta">' + esc(r.note) + "</span>" : "");
    document.querySelectorAll(".cltab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === tab)));
    const out = $("#cl-res-out");
    if (tab === "headers") out.innerHTML = r.headers.map(([k, v]) => '<span class="h-name">' + esc(k) + "</span>: " + esc(v)).join("\n");
    else if (tab === "code") out.textContent = r.snippet;
    else if (!r.text) out.innerHTML = '<span class="dim">(no body — ' + r.status + " " + esc(r.statusText) + ")</span>";
    else { try { out.innerHTML = highlight(JSON.stringify(JSON.parse(r.text), null, 2)); } catch (e) { out.textContent = r.text; } }
  }

  function snippetFor(method, path, headers, body) {
    const hs = Object.keys(headers).length ? "  headers: " + JSON.stringify(headers, null, 4).replace(/\n/g, "\n  ") + ",\n" : "";
    let bs = "";
    if (body) { try { bs = "  body: JSON.stringify(" + JSON.stringify(JSON.parse(body), null, 2).replace(/\n/g, "\n  ") + "),\n"; } catch (e) { bs = "  body: " + JSON.stringify(body) + ",\n"; } }
    return "// paste into your devtools console on this page\nconst res = await claims.fetch(" + JSON.stringify(path) + ", {\n  method: " + JSON.stringify(method) + ",\n" + hs + bs + "});\nconsole.log(res.status, res.headers.get('etag'));\nconsole.log(res.status === 204 || res.status === 304 ? null : await res.json());";
  }

  function track(status, method, path) {
    logItems.unshift({ status, method, path });
    logItems.length = Math.min(logItems.length, 12);
    $("#cl-log").innerHTML = logItems.map((l) => '<li><span class="m">' + esc(l.method) + '</span><span class="c' + String(l.status)[0] + '">' + l.status + '</span><span class="p" title="' + esc(l.path) + '">' + esc(l.path) + "</span></li>").join("");
  }

  /** Learn ids/etags/cursors from whatever just came back, so recipes chain. */
  function absorb(res, text, path) {
    const etag = res.headers.get("etag");
    const loc = res.headers.get("location");
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { /* no body */ }
    const bare = path.split("?")[0];
    if (data && data.object === "claim") { ctx.claimId = data.id; if (etag && res.ok) ctx.claimEtag = etag; }
    else if (loc && /\/claims\//.test(loc)) ctx.claimId = loc.split("/").pop();
    else if (/^\/v1\/claims\/[^/]+$/.test(bare) && res.status < 400) { ctx.claimId = bare.split("/").pop(); if (etag) ctx.claimEtag = etag; }
    if (data && data.object === "policy") ctx.policyId = data.id;
    else if (/^\/v1\/policies\/[^/]+$/.test(bare) && res.status < 400) ctx.policyId = bare.split("/").pop();
    if (data && data.page && data.page.next_cursor) ctx.cursor = data.page.next_cursor;
    const rem = res.headers.get("ratelimit-remaining");
    if (rem !== null) $("#cl-rate-meta").textContent = "API tokens " + rem + "/" + res.headers.get("ratelimit-limit");
  }

  /* ── sending ── */
  async function send() {
    const method = el.method.value;
    const path = el.path.value.trim() || "/v1";
    let headers;
    try { headers = parseHeaders(el.headers.value); new Headers(headers); } catch (e) {
      last = null;
      $("#cl-res-status").innerHTML = '<span class="pill s5">client error</span>';
      $("#cl-res-out").textContent = e.message;
      return;
    }
    const body = el.body.value.trim();
    const hasBody = body && method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
    if (hasBody && !Object.keys(headers).some((k) => k.toLowerCase() === "content-type")) headers["Content-Type"] = "application/json";
    el.send.disabled = true;
    const t0 = performance.now();
    try {
      const res = await api.fetch(path, { method, headers, body: hasBody ? body : undefined });
      const text = await res.text();
      absorb(res, text, path);
      last = {
        status: res.status, statusText: res.statusText, ms: Math.round(performance.now() - t0), size: new TextEncoder().encode(text).length, text,
        headers: [...res.headers.entries()].sort((a, b) => a[0].localeCompare(b[0])), snippet: snippetFor(method, path, headers, hasBody ? body : "")
      };
      track(res.status, method, path);
      renderResponse();
    } catch (e) {
      $("#cl-res-status").innerHTML = '<span class="pill s5">client error</span>';
      $("#cl-res-out").textContent = String(e);
    } finally {
      el.send.disabled = false;
      refresh();
    }
  }

  async function scenario(key) {
    const sc = SCENARIOS[key];
    el.send.disabled = true;
    const t0 = performance.now();
    const timeline = [];
    let result;
    try { result = await sc.run(timeline); } catch (e) { result = { error: String(e) }; }
    const text = JSON.stringify({ scenario: sc.title, timeline, ...result }, null, 2);
    last = {
      status: 200, statusText: "scenario", ms: Math.round(performance.now() - t0), size: text.length, text, headers: [["x-scenario", key]],
      snippet: "// every step is an ordinary API call, e.g.\nconst res = await claims.fetch('/v1/claims', {\n  method: 'POST',\n  headers: { Authorization: 'Bearer " + T.claimant + "', 'Content-Type': 'application/json' },\n  body: JSON.stringify({ policy_id: 'pol_auto_ada', type: 'collision', incident_date: '" + day(-3) + "', amount_claimed: 2600, description: 'Hit a pothole and bent the wheel.' })\n});\nconsole.log(res.status, await res.json());",
      note: "scenario · " + timeline.length + " steps"
    };
    track(200, "RUN", sc.title);
    tab = "body";
    renderResponse();
    el.send.disabled = false;
    refresh();
  }

  /* ── live tables + assessment card ── */
  const clip = (s, n) => { const t = String(s).replace(/\s+/g, " "); return t.length > n ? t.slice(0, n - 1) + "…" : t; };

  function renderAssess(c) {
    const box = $("#cl-assess");
    if (!c) { box.innerHTML = '<p class="empty">Select a claim to see how it was assessed.</p>'; return; }
    const a = c.assessment, cov = a.coverage, fr = a.fraud;
    const checks = a.eligibility.map((r) => '<li><span class="' + (r.passed ? "ok" : r.hard ? "no" : "soft") + '">' + (r.passed ? "✓" : r.hard ? "✗" : "!") + "</span><span><b>" + esc(r.rule) + "</b> " + esc(r.detail) + "</span></li>").join("");
    const rows = [
      ["Amount claimed", usd(c.amount_claimed), ""],
      ["− Deductible", "−" + usd(Math.min(cov.deductible, c.amount_claimed)), ""],
      ["− Your share (" + cov.coinsurance_pct + "% coinsurance)", "−" + usd(cov.amount_after_deductible - cov.insurer_share), ""],
      ["Insurer share", usd(cov.insurer_share), ""],
      ["Policy limit remaining", usd(cov.remaining_limit), cov.capped_by_limit ? "soft" : ""],
      ["Payable estimate", usd(cov.payable_estimate), "total"]
    ].map((r) => '<tr class="' + r[2] + '"><td>' + r[0] + "</td><td>" + r[1] + "</td></tr>").join("");
    const flags = fr.flags.length ? fr.flags.map((f) => "<li><b>+" + f.weight + "</b> " + esc(f.code) + " <span class=\"sub inline\">" + esc(f.detail) + "</span></li>").join("") : '<li class="sub">No red flags.</li>';
    const color = fr.band === "high" ? "var(--bad)" : fr.band === "medium" ? "var(--warn)" : "var(--ok)";
    box.innerHTML =
      '<div class="assess-top"><div><span class="name">' + esc(c.claim_number) + '</span><span class="sub">' + esc(c.type) + " on " + esc(c.policy_id) + " · " + esc(c.incident_date) + '</span></div><span class="badge ' + c.status + '">' + c.status.replace("_", " ") + "</span></div>" +
      '<div class="route ' + a.routing.path + '"><b>' + esc(a.routing.path) + "</b> · " + esc(a.routing.reason) + "</div>" +
      (c.decision ? '<p class="sub dec"><b>' + esc(c.decision.by) + "</b> " + esc(c.decision.outcome) + ": " + esc(c.decision.reason || "—") + "</p>" : "") +
      "<div><h4>Eligibility</h4><ul class=\"checks\">" + checks + "</ul></div>" +
      "<div><h4>Coverage maths</h4><table class=\"money\"><tbody>" + rows + "</tbody></table></div>" +
      '<div><h4>Fraud score <span style="color:' + color + '">' + fr.score + " · " + fr.band + '</span></h4><div class="meter-bar"><i style="width:' + fr.score + "%;background:" + color + '"></i></div><ul class="flags">' + flags + "</ul></div>";
  }

  function refresh() {
    const showDeleted = $("#cl-show-deleted").checked;
    const claims = api.peekClaims();
    const policies = api.peekPolicies();
    if (!claims.some((r) => r.id === ctx.claimId)) { const f = claims.find((r) => !r.deleted_at) || claims[0]; ctx.claimId = f ? f.id : ""; }
    const cur = claims.find((r) => r.id === ctx.claimId);
    if (cur) ctx.claimEtag = cur.etag;
    if (!policies.some((p) => p.id === ctx.policyId)) ctx.policyId = (policies.find((p) => p.status === "active") || policies[0] || {}).id || "";
    const flash = (r) => (booted && seen.get(r.id) !== r.version ? "flash" : "");

    $("#cl-claims-body").innerHTML = claims.filter((r) => showDeleted || !r.deleted_at).map((r) => {
      const fr = r.assessment.fraud;
      return '<tr tabindex="0" data-kind="claim" data-id="' + esc(r.id) + '" class="' + (r.id === ctx.claimId ? "is-selected " : "") + (r.deleted_at ? "is-deleted " : "") + flash(r) + '">' +
        '<td class="wide"><span class="name">' + esc(clip(r.description, 46)) + '</span><span class="sub">' + esc(r.claim_number) + " · " + esc(r.type) + " · " + esc(r.policy_id) + " · v" + r.version + "</span></td>" +
        "<td>" + usd(r.amount_claimed) + '<span class="sub">' + (r.paid_amount != null ? "paid " + usd(r.paid_amount) : r.approved_amount != null ? "approved " + usd(r.approved_amount) : "est. " + usd(r.assessment.coverage.payable_estimate)) + "</span></td>" +
        '<td><span class="badge ' + fr.band + '">' + fr.band + '</span><span class="sub">score ' + fr.score + "</span></td>" +
        '<td><span class="badge ' + r.status + '">' + r.status.replace("_", " ") + '</span><span class="sub">' + esc(r.assessment.routing.path) + "</span></td></tr>";
    }).join("") || '<tr><td colspan="4" class="empty">No claims. File one above, or reset the sandbox.</td></tr>';

    $("#cl-policies-body").innerHTML = policies.map((p) => {
      const used = p.limit - p.usage.remaining_limit;
      const pct = Math.min(100, Math.round((used / p.limit) * 100));
      return '<tr tabindex="0" data-kind="policy" data-id="' + esc(p.id) + '" class="' + (p.id === ctx.policyId ? "is-selected " : "") + flash(p) + '">' +
        '<td><span class="name">' + esc(p.holder) + '</span><span class="sub">' + esc(p.product) + " · " + esc(p.id) + "</span></td>" +
        '<td><span class="badge ' + (p.status === "active" ? "released" : "expired") + '">' + p.status + '</span></td>' +
        '<td><div class="meter-bar slim"><i style="width:' + pct + '%"></i></div><span class="sub">' + usd(used) + " of " + usd(p.limit) + "</span></td></tr>";
    }).join("");

    renderAssess(cur);
    claims.forEach((r) => seen.set(r.id, r.version));
    policies.forEach((r) => seen.set(r.id, r.version));
    booted = true;
    renderVars();
  }

  function openRow(e) {
    const tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    if (tr.dataset.kind === "policy") { ctx.policyId = tr.dataset.id; load({ method: "GET", path: "/v1/policies/{{policy}}" }); }
    else { ctx.claimId = tr.dataset.id; load({ method: "GET", path: "/v1/claims/{{claim}}" }); }
    refresh();
    send();
  }
  $("#cl-claims-body").addEventListener("click", openRow);
  $("#cl-policies-body").addEventListener("click", openRow);
  [$("#cl-claims-body"), $("#cl-policies-body")].forEach((b) => b.addEventListener("keydown", (e) => { if (e.key === "Enter") e.target.closest("tr[data-id]")?.click(); }));
  $("#cl-show-deleted").addEventListener("change", refresh);
  $("#cl-reset").addEventListener("click", () => { load({ method: "POST", path: "/v1/sandbox/reset", headers: [AUTH_A] }); send(); });
  document.querySelectorAll(".cltab").forEach((t) => t.addEventListener("click", () => { tab = t.dataset.tab; renderResponse(); }));
  el.send.addEventListener("click", send);
  [el.path, el.headers, el.body].forEach((f) => f.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); send(); } }));
  // Other parts of the page (e.g. the hero laptop's spacebar) can ask for a scenario to run.
  window.addEventListener("claims:run", (e) => {
    if (!SCENARIOS[e.detail]) return;
    const start = () => (el.send.disabled ? setTimeout(start, 150) : scenario(e.detail)); // wait if a request is in flight
    start();
  });

  /* ── boot ── */
  renderRecipes();
  refresh();
  load(RECIPES[1].items[0]);
  send();
  api.fetch("/v1/stats").then((r) => r.json()).then((s) => {
    if (noteEl) noteEl.textContent = "Roodie Insuretech API: " + s.claims.total + " claims, " + Math.round(s.claims.straight_through_rate * 100) + "% processed straight-through, " + usd(s.money.paid) + " paid.";
  }).catch(() => { if (noteEl) noteEl.textContent = "The Roodie Insuretech API engine is unreachable."; });
})();
