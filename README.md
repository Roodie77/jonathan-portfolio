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

## Project layout

```
index.html     the portfolio, including the API console UI
xeno-api.js    the whole API engine (no dependencies)
```

## Honest limitations

- It's a sandbox. Data lives in one browser's `localStorage`, and there's a single demo token.
- The detectors are heuristics and will have both misses and false positives. That's what the review workflow and the policy threshold are for.
- It simulates a server, so other apps can't call it over the network. If I host it for real, the engine is written to port cleanly to a Node backend.
- The guard's attempt windows are held in memory, so they reset on page reload. Bans, cases and policies persist.

## Author

Built by **Jonathan** · [GitHub @Roodie77](https://github.com/Roodie77)
