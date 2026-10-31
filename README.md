# Xeno: two APIs, one portfolio

This repo holds two backend projects that run live inside my portfolio site:

- **[Xeno Shield API](#xeno-shield-api)**: quarantines bad data and stops brute-force and abuse attacks.
- **[Roodie Insuretech API](#roodie-insuretech-api)**: an insurance claims engine with coverage maths, fraud scoring, adjuster decisions, payouts and appeals.

Both are built the same way (real HTTP semantics, no dependencies, runs in the browser or in Node), so the engineering patterns carry across: ETag concurrency, idempotency, problem+json errors, cursor pagination and audit history.

---

# Xeno Shield API

A defensive API for websites and apps. It has two jobs:

1. **Quarantine bad data.** Screen incoming form fields for SQL injection, XSS, path traversal, command injection, log4shell, obfuscated payloads and encoded evasions. The suspicious ones are held in a quarantine where a human can review them.
2. **Stop abuse.** Spot brute force, credential stuffing, password spraying and distributed attacks on a single account, then answer allow, throttle or block, with bans that get longer for repeat offenders.

I'm Jonathan ([@Roodie77](https://github.com/Roodie77)). I built this into my portfolio because I wanted an API demo you can actually attack, not another to-do list.

## Try it

Open the portfolio and scroll to the **Live API** section. There are one-click recipes for every operation, **attack simulations** you can launch at the guard, and a **Break it** row that triggers every error on purpose. Everything is editable: method, path, headers, body.

Or open devtools on the page and call it directly:

```js
const res = await xeno.fetch('/v1/inspections', {
  method: 'POST',
  headers: { Authorization: 'Bearer xeno_demo_key', 'Content-Type': 'application/json' },
  body: JSON.stringify({ source: 'login-form', fields: { username: "admin' OR '1'='1' --" } })
});
console.log(await res.json());   // verdict: "quarantine", with the findings that triggered it
```

## One thing to know up front

There's no server. My portfolio is a static site, so the whole API runs **inside your browser** and keeps its data in `localStorage`. Nothing you do leaves your machine, and "Reset sandbox" restores the seed data.

It isn't a mock that returns canned JSON. [`xeno-api.js`](xeno-api.js) is a real engine: it routes requests, validates them, enforces rules, and returns genuine `Response` objects through a `fetch()`-compatible function. The same file runs in Node (`require('./xeno-api.js')`), which is how I tested it.

## Job 1: quarantining bad data

Send the fields from a form to `POST /v1/inspections`:

```json
{
  "source": "contact-form",
  "fields": {
    "name": "Ada Lovelace",
    "message": "<img src=x onerror=alert(document.cookie)>"
  }
}
```

Each field is scored by a set of detectors. Fields at or above the policy threshold (default 40) are quarantined; the rest pass:

```json
{
  "verdict": "quarantine",
  "threshold": 40,
  "results": [
    { "field": "name", "verdict": "allow", "score": 0, "reason": "clean" },
    {
      "field": "message",
      "verdict": "quarantine",
      "score": 50,
      "severity": "medium",
      "categories": ["xss"],
      "findings": [{ "rule": "xss.event-handler", "weight": 50, "evidence": "<img src=x onerror=" }],
      "case_id": "qr_0mvf…"
    }
  ]
}
```

**What it catches:** SQL injection (tautologies, `UNION SELECT`, stacked queries, time-based), XSS (script tags, event handlers, `javascript:` URIs, embeds), path traversal, command injection, log4shell and template injection, prototype pollution, null bytes, `eval`/`atob` obfuscation, long base64 blobs, and oversized fields.

**It doesn't get fooled by simple evasion.** Input is Unicode-normalised and URL-decoded (twice) before matching, so `%253Cscript%253E` and fullwidth `＜script＞` are caught, and the finding says the payload only matched after decoding.

**It learns from reviewers.** Each quarantined item is a *case*. When a reviewer marks one `released` (a false positive), the same payload from the same source is allowed through next time. Mark one `confirmed` and repeats are flagged as known-malicious. Identical repeats don't create duplicates, they bump a `hits` counter.

`mode: "monitor"` is a dry run: it reports findings but stores nothing, which is handy for rolling this out without blocking anyone.

These are heuristic detectors, good for screening and triage. They're a layer in front of your own parameterised queries and output encoding, not a replacement for them.

### The review workflow

```
quarantined ──► released     (false positive)
     │
     └────────► confirmed    (really malicious)
```

Released and confirmed cases can be re-opened back to `quarantined`; any other jump is a `409`. Business rules are enforced too:

- The captured **payload is immutable**. Evidence can't be edited after the fact.
- Releasing a **critical**-severity case needs a `reviewer_note` of at least 10 characters.
- A case with no detector findings can't be confirmed as malicious.

## Job 2: stopping abuse

Call `POST /v1/guard/attempts` on every login, signup, password reset or API call, and act on the answer:

```json
{ "scope": "login", "ip": "203.0.113.7", "identity": "admin", "outcome": "failure", "secret_fingerprint": "pw_5f4dcc3b" }
```

| Decision | HTTP | Meaning |
|---|---|---|
| `allow` | 200 | Carry on |
| `throttle` | 429 | Approaching the limit. `Retry-After` tells you how long to back off |
| `block` | 403 | Banned. The response says why, and for how long |

`secret_fingerprint` is a **hash** of whatever was tried, never a real password. It's how password spraying gets spotted.

It tells apart four different attacks:

| Attack | How it looks | What gets banned |
|---|---|---|
| **Brute force** | Many failures from one IP | the IP |
| **Credential stuffing** | One IP trying many different accounts | the IP |
| **Password spraying** | One password hash tried across many accounts (even from many IPs) | the password fingerprint |
| **Distributed attack** | Many IPs all hammering one account | the account (identity) |

Bans **escalate**. The first ban on a subject lasts the policy's base duration. If the same subject offends again within 24 hours, each ban multiplies (default 2×) up to a cap. A successful login clears the failure counters for that IP and account. Banned traffic never inflates its own counters, so you can see exactly who's still knocking (`hits` on the ban).

In the demo, hit the four **Abuse guard** simulation buttons and watch the registry fill with bans. There's also `GET /v1/guard/status`, a read-only "is this subject blocked?" check that's handy in middleware.

### Policies

Every threshold is tunable with `PATCH /v1/policies/{scope}`. Scopes are `login`, `signup`, `api`, `password-reset` and `inspection`:

```json
{ "window_seconds": 60, "max_failures": 5, "max_identities": 8, "spray_threshold": 5,
  "ban_base_seconds": 60, "ban_multiplier": 2, "ban_max_seconds": 86400, "counts": "failures" }
```

## Endpoints

Base path is `/v1`. Reads are open. Writes need `Authorization: Bearer xeno_demo_key` (prefilled in the console).

| Method | Path | What it does |
|---|---|---|
| POST | `/inspections` | Screen fields or a payload; quarantines suspicious ones |
| GET · POST | `/quarantine` | List (filters, search, sort, cursor paging) · add a case manually |
| GET · PUT · PATCH · DELETE | `/quarantine/{id}` | Read · replace · review/edit · soft delete |
| POST | `/quarantine/{id}/restore` | Undo a delete |
| GET | `/quarantine/{id}/history` | Full change log |
| POST | `/guard/attempts` | Report an attempt, get allow / throttle / block |
| GET | `/guard/status` | Is this ip / identity / fingerprint blocked? |
| GET · POST | `/bans` | List · ban manually |
| GET · PUT · PATCH · DELETE | `/bans/{id}` | Read · replace · extend/edit · lift |
| POST | `/bans/{id}/restore` | Re-apply a lifted ban |
| GET | `/bans/{id}/history` | Full change log |
| GET · PATCH | `/policies`, `/policies/{scope}` | Read and tune thresholds |
| GET | `/stats` | Cases, bans, inspections and guard decisions |
| POST | `/sandbox/reset` | Reseed the demo data |

`HEAD` and `OPTIONS` work too, and a wrong method returns `405` with an `Allow` header.

Quarantine filters: `status`, `severity`, `category`, `label`, `source`, `min_score`, `q`. Ban filters: `kind`, `scope`, `active`, `q`. Both support `sort`, `fields` and `include_deleted`.

## The API hygiene

The security features sit on top of API basics I wanted to get right:

- **Safe concurrent edits.** Every record has an `ETag`. `PUT`, `PATCH` and `DELETE` must send it back in `If-Match`. Forget it and you get `428`; send a stale one and you get `412`.
- **Retry-safe creates.** Send an `Idempotency-Key` on `POST /quarantine` or `POST /bans` and a retry replays the original response instead of duplicating.
- **JSON Merge Patch (RFC 7396)** for partial updates. A patch that changes nothing returns `200` without bumping the version.
- **Soft delete.** Deleting leaves a tombstone: reading it returns `410 Gone` with a link to restore it, and `DELETE ?purge=true` removes it permanently. Lifting a ban works the same way, and the tombstone keeps its history so escalation still works.
- **Errors you can act on.** Failures are `application/problem+json` (RFC 9457) with a request id and a JSON pointer to each bad field.
- **Keyset cursor pagination.** Results don't skip or repeat when data changes between pages.
- **The API protects itself too.** A token-bucket limit (60 burst, refilling 10/s) returns `429` with `Retry-After` and `RateLimit-*` headers. The **flood the API ×80** button shows it.

## Status codes you'll meet

`200` `201` `204` `304` · `400` bad input or cursor · `401` no or bad token · `403` guard blocked the attempt · `404` `405` · `409` conflict, duplicate or illegal transition · `410` deleted · `412` stale ETag · `415` wrong content type · `422` validation or business rule · `428` missing `If-Match` · `429` slow down

## Honest limitations (Shield)

- It's a sandbox. Data lives in one browser's `localStorage`, and there's a single demo token.
- The detectors are heuristics and will have both misses and false positives. That's what the review workflow and the policy threshold are for.
- It simulates a server, so other apps can't call it over the network. If I host it for real, the engine is written to port cleanly to a Node backend.
- The guard's attempt windows are held in memory, so they reset on page reload. Bans, cases and policies persist.

---

# Roodie Insuretech API

I'm studying insurance and I write backends, so this is where the two meet: an API that handles an insurance claim the way a real insurer does, and **shows its working** at every step.

Try it in the **Claims** section of the portfolio. Click any claim to see *why* it was routed the way it was, or run one of the scripted scenarios. Or from devtools:

```js
const res = await claims.fetch('/v1/claims?risk=high&sort=-fraud_score');
console.log(await res.json());
```

## How a claim flows

```
claimant files ──► eligibility ──► coverage maths ──► fraud score ──► routing
                                                                        │
        ┌───────────────────┬──────────────────┬────────────────────────┘
        ▼                   ▼                  ▼                       ▼
  straight-through       adjuster             SIU                auto-denied
  (approved at once)   (under review)   (special investigation)   (with reason codes)
```

`POST /v1/claims` runs all of this in one request and returns the claim with its full **assessment**:

```json
{
  "claim_number": "CLM-2026-000018",
  "status": "under_review",
  "assessment": {
    "eligibility": [
      { "rule": "policy.active", "hard": true, "passed": true, "detail": "Policy is active." },
      { "rule": "policy.waiting-period", "hard": true, "passed": true, "detail": "No waiting period." }
    ],
    "coverage": { "amount_after_deductible": 1350, "insurer_share": 1350, "remaining_limit": 20000, "payable_estimate": 1350 },
    "fraud": { "score": 35, "band": "medium", "flags": [{ "code": "possible-duplicate", "weight": 35, "detail": "…" }] },
    "routing": { "path": "adjuster", "reason": "Fraud band is \"medium\" (score 35)." }
  }
}
```

**Eligibility.** Hard rules (policy active, incident inside the policy period, waiting period served, claim type covered, limit remaining, filed within 60 days) cause an automatic denial with reason codes. Soft rules (exclusion wording such as "racing") don't deny on a keyword alone; they send the claim to a human, because wording can mislead.

**Coverage maths.** `payable = min((claimed − deductible) × (1 − coinsurance%), remaining limit)`. The remaining limit shrinks as claims are approved and paid.

**Fraud scoring.** Transparent, weighted red flags: possible duplicate, claim soon after the policy started, frequent claims, amount near the policy limit, amount far above typical for that type, suspicious wording, late filing and suspiciously round amounts. Below 25 is low, 25–49 medium, 50+ high.

**Routing.** High fraud risk goes to special investigations. Low risk, fully eligible and under the policy's auto-approve limit is approved straight away. Everything else goes to an adjuster.

## Lifecycle and roles

```
under_review ─► approved ─► paid
     │  ▲  ╲
     │  │   └► denied ─► appealed ─► (decided again)
     ▼  │
info_requested        siu_review ─► approved / denied
```

| Role | Token | Can do |
|---|---|---|
| claimant | `claimant_demo_key` | file, edit while pending, add documents, appeal, withdraw |
| adjuster | `adjuster_demo_key` | decide, pay, restore, issue and amend policies |

Reads are open in the sandbox. The wrong role gets `403`, no token gets `401`. Status is never written directly; it moves through actions:

- `POST /claims/{id}/decision` with `approve`, `deny`, `request_info` or `escalate`. Approving above what's payable is a `422`. Approving an SIU-flagged claim, or overriding a failed eligibility rule, needs a written justification.
- `POST /claims/{id}/pay` pays an approved claim. Paying twice is a `409`.
- `POST /claims/{id}/appeal` re-opens a denied claim **once**, within 30 days.
- `POST /claims/{id}/documents` attaches a document and sends an `info_requested` claim back to review.

## Endpoints

| Method | Path | Who | What it does |
|---|---|---|---|
| GET | `/v1/policies`, `/v1/policies/{id}` | anyone | Policies, with live usage (paid, reserved, remaining limit) |
| POST · PUT · PATCH | `/v1/policies`, `/v1/policies/{id}` | adjuster | Issue and amend. Policies are cancelled, never deleted |
| GET · POST | `/v1/claims` | anyone · claimant | List (filters, sort, cursor paging) · file a claim |
| GET · PATCH · DELETE | `/v1/claims/{id}` | anyone · claimant | Read · edit amount/description while pending · withdraw |
| POST | `/v1/claims/{id}/decision` | adjuster | approve / deny / request_info / escalate |
| POST | `/v1/claims/{id}/pay` | adjuster | Pay an approved claim |
| POST | `/v1/claims/{id}/appeal` | claimant | Appeal a denial |
| POST | `/v1/claims/{id}/documents` | claimant | Attach a document |
| POST | `/v1/claims/{id}/restore` | adjuster | Undo a withdrawal |
| GET | `/v1/claims/{id}/history`, `/v1/policies/{id}/history` | anyone | Audit trail with who did what |
| GET | `/v1/stats` | anyone | Straight-through rate, flagged rate, money, **loss ratio per product** |

Claim filters: `status`, `type`, `risk`, `path`, `policy_id`, `min_amount`, `max_amount`, `q`. Sort by `created_at`, `amount_claimed`, `fraud_score`, `incident_date`.

## The parts I care about

- **A payout must never happen twice.** `POST …/pay` honours `Idempotency-Key`, and the scenario **Double-pay attempt** fires three simultaneous pay requests and produces exactly one payment reference. A keyless second payment is refused with `409`.
- **Two adjusters can't clobber each other.** Decisions need `If-Match`. The scenario **Two adjusters collide** shows the second adjuster's stale write getting `412`, and then `409` once they re-read and see the claim is already approved.
- **Duplicates are flagged, not blocked.** Filing the same loss twice is a fraud signal, not a validation error, so the second claim is accepted but scored and routed. The same `Idempotency-Key` still replays instead of filing a third.
- **Financial records are never deleted.** Withdrawing a claim is a soft delete (`410 Gone`, restorable by an adjuster). `?purge=true` is refused with `409`.
- **Business rules are enforced, not assumed.** A policy can't be sold coverage its product doesn't offer, its limit can't drop below what's already paid or reserved, a cancelled policy stays cancelled, and `policy_id`, `type` and `incident_date` are immutable once a claim is filed.
- **Everything is explainable.** Every decision stores who made it, when and why, and the history endpoint shows the full trail with the actor (claimant, adjuster or system).

The shared hygiene from the Shield API applies here too: ETag/`If-Match` on writes (`428`/`412`), JSON Merge Patch, RFC 9457 problem+json errors, keyset cursor pagination and a token-bucket rate limit.

## Honest limitations (Claims)

- Sandbox only. It's a simulated server with `localStorage`, two demo tokens, and open reads. A real system would scope reads so a claimant only sees their own claims.
- The fraud rules are a simple weighted heuristic with made-up weights, not an actuarial or machine-learning model. The point is that the logic is transparent and tunable.
- Deductible is applied per claim, and there's no tax, subrogation, partial payments, reinsurance or document file storage. Documents are metadata only.
- Money is plain numbers rounded to cents. A real ledger would use integer minor units and double-entry accounting.

---

---

# Test both APIs with curl

The two engines also run as a **real HTTP server** on your own machine. That means you can hit them with curl, Postman or any HTTP client, not just the in-browser consoles.

```bash
git clone https://github.com/Roodie77/jonathan-portfolio.git
cd jonathan-portfolio
node server.js --fresh              # Node 18+, no npm install; leave it running
```

In a second terminal:

```bash
source scripts/curl-helpers.sh      # bash or zsh (Git Bash/WSL on Windows)
api $INS                            # Roodie Insuretech API index
api "$SHD/quarantine?severity=high,critical"
```

| API | Base URL |
|---|---|
| Roodie Insuretech API | `http://localhost:3000/insuretech/v1` |
| Xeno Shield API | `http://localhost:3000/shield/v1` |

The server binds to `127.0.0.1` only, so nothing is exposed to the network, and it saves state in `./data` between runs (`--fresh` resets it). `api` is just curl plus the HTTP status and pretty-printed JSON; replace it with `curl` to see raw output.

**[roodie-api-curl-guide.pdf](roodie-api-curl-guide.pdf)** is a 13-page walkthrough with **46 commands** across both APIs: filing and routing claims, ETag and role errors, idempotent payments, input screening with evasion, a real brute-force loop (`200 200 429 429 403 403…`) and password spraying. Every command in it was executed against this server with real curl, and the "Expect" lines are what came back. The guide is also on the portfolio site.

Demo tokens: `claimant_demo_key` and `adjuster_demo_key` (Insuretech), `xeno_demo_key` (Shield). Reads need no token.

---

## Project layout

```
index.html                    the portfolio, including both API sections
xeno-api.js                   Shield engine (no dependencies)
claims-api.js                 Insuretech engine (no dependencies)
claims-console.js             the Insuretech test console UI
server.js                     real HTTP server for both engines (local only)
scripts/curl-helpers.sh       api / field / etag / day helpers for curl
roodie-api-curl-guide.pdf     the curl test guide
package.json                  `npm start` runs the server
jonathan-profile.jpg
```

## Author

Built by **Jonathan** · [GitHub @Roodie77](https://github.com/Roodie77)
