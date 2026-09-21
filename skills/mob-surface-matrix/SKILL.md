---
name: mob-surface-matrix
description: Use when hunting phase begins or when starting analysis of any app with a traffic sample. Maps every endpoint from the traffic capture to every applicable attack vector from the BSCP and MOSRAI skill libraries, generating an exhaustive endpoint-by-vector matrix. This is a mandatory step between Recon and Hunting: no vector testing starts until the matrix is built and the operator has reviewed coverage. Triggers - "attack surface matrix", "coverage matrix", "mapear vectores", "surface mapping", "endpoint mapping", "what vectors apply", "blind spots", "mob-surface-matrix"
platform: [android, ios]
stack: [any]
category: recon
tier: A
related: [mob-analyze, mob-enabling, mob-flutter, mob-native, mob-react-native, mob-capacitor]
---

# Attack Surface Matrix

This skill generates an exhaustive mapping of every endpoint in the app's attack surface to every applicable attack vector from the BSCP and MOSRAI skill libraries. The output is a structured matrix that the Hunting phase works through systematically, eliminating blind spots.

## Why this exists

Without this skill, the agent picks vectors based on what seems interesting. That leaves gaps: the agent tries IDOR and misses path traversal, or tests SSRF on one endpoint and ignores it on another. This skill makes the coverage systematic, not accidental.

## When to run

After Recon (surface mapped, endpoints identified) and BEFORE Hunting (any vector testing). If new endpoints appear mid-engagement (from decompilation, from traffic, from source review), regenerate the matrix.

## Inputs

| Source | What to extract |
|---|---|
| Burp MCP (proxy history) | method, path, params, headers, auth type, body |
| HAR export | same |
| Source code (white-box) | routes, handlers, middleware |
| Context pack | business flows, credentials, known defenders |
| engagement.state | app stack, platform, scope |

## Phase A: Extract endpoints

From every source above, extract all unique endpoints:

```
METHOD | PATH | AUTH | PARAMS | BODY TYPE | HEADERS | NOTES
```

Deduplicate by (METHOD, PATH). For each endpoint, record:

- **Path**: the route (with parameters, e.g. `/api/meetings/:id`)
- **Method**: GET, POST, PUT, DELETE, PATCH
- **Auth**: none, Bearer token, session cookie, API key, custom header
- **Parameters**: path params, query params, body fields (mark client-controllable ones)
- **Body type**: JSON, multipart/form-data, XML, raw
- **Headers**: Content-Type, custom headers, auth headers
- **Response type**: JSON, HTML, file download, redirect
- **Source**: where this endpoint was found (proxy, source code, decompilation)

## Phase B: Classify each endpoint

For each endpoint, assign one or more classifications:

| Classification | Signal |
|---|---|
| **object-read** | GET with a path/query parameter that references a resource (e.g. `:id`, `:userId`, `:file`) |
| **object-write** | POST/PUT/PATCH with a body that modifies a resource |
| **object-delete** | DELETE with a path/query parameter |
| **auth-flow** | Endpoint in the auth path (login, token exchange, refresh, register) |
| **auth-required** | Requires an auth header/cookie to access |
| **file-upload** | Accepts file uploads (multipart, base64 in body) |
| **file-download** | Returns file content (PDF, image, export) |
| **email-out** | Sends email (support, notifications) |
| **llm-processed** | Body content is fed to an LLM (transcription, chatbot, analysis) |
| **search** | Accepts search/filter parameters |
| **admin** | Admin-only endpoints (role-restricted) |
| **payment** | Handles payments, amounts, billing |
| **user-data** | Returns or processes personal data (PII) |
| **third-party-callback** | Receives callbacks from external services (OAuth, webhooks) |
| **deep-link** | Deep link / URL scheme handler |
| **websocket** | WebSocket connection |
| **graphql** | GraphQL endpoint |

## Phase C: Map classifications to vectors

For each endpoint, list ALL applicable vectors using this taxonomy. Each vector references the skill that documents the methodology.

### Vector taxonomy by classification

#### object-read (GET with resource reference)
| Vector | Skill | Why |
|---|---|---|
| IDOR / BOLA (substitute identifier) | bscp-access-control v10 | Path param may not validate ownership |
| Auth bypass (no token) | bscp-access-control v1 | Check if auth is enforced |
| Auth bypass (different user token) | bscp-access-control v2 | Cross-user access |
| Verbose response (data over-exposure) | bscp-information-disclosure v5 | Response may return more data than needed |
| SQL injection (in path param) | bscp-sql-injection v1-13 | Path params may reach DB queries |
| Path traversal (in path param) | bscp-path-traversal v1 | Path params may reach file system |
| Race condition (concurrent reads) | bcp-race-conditions v4 | If the resource is stateful |

#### object-write (POST/PUT/PATCH with body)
| Vector | Skill | Why |
|---|---|---|
| Mass assignment (add extra fields) | bscp-api-testing v5 | Server may accept unintended fields |
| IDOR / BOLA (modify other user's resource) | bscp-access-control v10 | Check ownership validation |
| Parameter pollution (duplicate params) | bscp-api-testing v6-8 | Server may use first/last value |
| Business logic tamper (negative amounts, invalid states) | bscp-business-logic v1-3 | Values may not be validated server-side |
| Injection (SQL, NoSQL, command) in body fields | bscp-sql-injection, bscp-nosql-injection | Body fields may reach DB or shell |
| SSRF (URL fields in body) | bscp-ssrf-attacks v1 | URL fields may be fetched server-side |
| Prototype pollution (JSON `__proto__`) | bscp-prototypepollution v5 | Server-side JS may merge objects unsafely |
| Race condition (concurrent writes) | bcp-race-conditions v1 | If the resource is limited |

#### auth-flow (login, token, refresh)
| Vector | Skill | Why |
|---|---|---|
| Username enumeration (different responses) | bscp-authentication v1-2 | Response may differ for valid/invalid users |
| Brute force / rate limiting bypass | bscp-authentication v4 | Check for rate limit on login |
| Password reset logic flaw | bscp-authentication v11-12 | Reset token may be predictable |
| Token forgery (known secret) | bscp-jwt v1-9 | If the secret is hardcoded or weak |
| Algorithm confusion (RS256 to HS256) | bscp-jwt v8 | If the JWT uses asymmetric keys |
| Session management flaw | bscp-authentication v16 | Session may not expire or be predictable |
| OAuth flow manipulation | bscp-oauth v1-6 | Redirect URI, state validation |

#### file-upload (multipart or base64 body)
| Vector | Skill | Why |
|---|---|---|
| File extension bypass | bscp-file-upload-vulnerabilities v4 | Server may block some extensions |
| Content-type bypass | bscp-file-upload-vulnerabilities v2 | Server may validate Content-Type header only |
| Path traversal in filename | bscp-file-upload-vulnerabilities v3 | Filename may not be sanitized |
| Malicious file content (polyglot) | bscp-file-upload-vulnerabilities v5 | File may be parsed by another component |
| LLM prompt injection via file content | llm-prompt-injection-multiframe | If file content feeds an LLM |
| SSRF via URL in file | bscp-ssrf-attacks v1 | If file references URLs (e.g. HLS playlist) |

#### email-out (HTML email)
| Vector | Skill | Why |
|---|---|---|
| XSS in email template (HTML injection) | bscp-xss v7 | Email may not escape user content |
| Server-side template injection | bscp-server-side-template-injection v1 | Template may interpolate user data |
| Info disclosure in email headers | bscp-information-disclosure v1 | Headers may reveal server info |

#### llm-processed (content fed to LLM)
| Vector | Skill | Why |
|---|---|---|
| Direct prompt injection | llm-prompt-injection-multiframe | Model may follow embedded instructions |
| Indirect prompt injection (via stored content) | coae-indirect-prompt-injection | Content may be read by LLM later |
| Excessive agency (LLM with dangerous tools) | bcp-llm-attacks v2 | LLM may have access to APIs |
| Data exfiltration via LLM output | coae-llm-markdown-exfiltration | LLM output may be rendered in HTML |
| Insecure output handling (XSS via LLM) | bcp-llm-attacks v10 | LLM output may contain HTML/JS |

#### search (search/filter params)
| Vector | Skill | Why |
|---|---|---|
| SQL injection (in search terms) | bscp-sql-injection v1-13 | Search may reach DB queries |
| NoSQL injection (in search operators) | bscp-nosql-injection v2 | Search may use MongoDB operators |
| Information disclosure (search reveals data) | bscp-information-disclosure | Search may return other users' data |

#### admin (admin-only endpoints)
| Vector | Skill | Why |
|---|---|---|
| Privilege escalation (access with lower role) | bscp-access-control v3 | Admin check may be client-side only |
| Dangerous endpoint exploitation | bscp-api-testing v2 | Admin endpoints may have untested functionality |

#### deep-link (URL scheme handler)
| Vector | Skill | Why |
|---|---|---|
| Deep link hijacking (no auth check) | deeplink-hijack-unverified-applinks | Link may bypass auth |
| Deep link parameter injection | deeplink-stored-xss-webview | Params may be reflected unsafely |
| Intent redirection | deeplink-exported-activity | Exported activity may be triggered externally |

#### payment (amounts, billing)
| Vector | Skill | Why |
|---|---|---|
| Amount tampering (negative, zero, overflow) | bscp-business-logic v2 | Amounts may not be validated server-side |
| Currency manipulation | bscp-business-logic v1 | Currency codes may not be validated |
| Race condition (double payment) | bcp-race-conditions v1 | Payment state may be race-prone |

#### websocket
| Vector | Skill | Why |
|---|---|---|
| Message manipulation | bscp-websockets v1 | WebSocket messages may not be validated |
| Cross-site WebSocket hijacking | bscp-websockets v4 | Origin check may be missing |
| Auth bypass via WS | bscp-websockets v2 | Auth may not be enforced on WS |

#### graphql
| Vector | Skill | Why |
|---|---|---|
| Introspection enabled | bscp-graphql-api-vulnerabilities v2 | Schema may be exposed |
| IDOR via GraphQL args | bscp-graphql-api-vulnerabilities v3 | Object references may not be validated |
| Rate limit bypass via aliases | bscp-graphql-api-vulnerabilities v5 | Aliases may bypass rate limiting |
| GraphQL CSRF | bscp-graphql-api-vulnerabilities v6 | CSRF may not be enforced |

## Phase D: Generate the matrix

Create `attack-surface-matrix.md` in the engagement directory using the template. The matrix is:

1. **A table per endpoint** listing every applicable vector
2. **A coverage summary** per skill BSCP showing: applied / tested / confirmed / discarded / pending / gap
3. **A blind spot report** listing any skill BSCP with zero applicable vectors (and why)

## Phase E: Operator review

Present the matrix to the operator. The operator can:

1. **Approve** the matrix as-is
2. **Add vectors** the agent missed (operator knows the business)
3. **Remove vectors** that are clearly out of scope
4. **Prioritize** which vectors to test first

No vector testing starts until the operator approves the matrix. This is a human gate.

## Rules

1. **No vector testing before the matrix is built.** The matrix comes first.
2. **Every endpoint gets classified.** No "this one looks fine, skip it."
3. **Every classification gets ALL its vectors.** No cherry-picking.
4. **Every vector references its source skill.** The agent must read the skill before testing.
5. **The operator approves the matrix before hunting starts.** This is the gate.
6. **New endpoints found during hunting** go back to Phase A. The matrix is a living document.
7. **The coverage summary is not optional.** It proves exhaustiveness (or exposes gaps).

## Integration with the cycle

The ASM fits between Recon (Step 4) and the human review of findings:

```
Step 4: Test
  ├── Phase 0: Enabling
  ├── Phase 1: Recon (surface map)
  ├── Phase 1.5: Attack Surface Matrix  ← THIS SKILL
  ├── Phase 2: Traffic analysis
  ├── Phase 3: Hunting (works THROUGH the matrix)
  └── Phase 4: First cut (results from the matrix)
Step 6-8: Human review
```

The first-cut findings come from the matrix results, not from "what the agent found interesting." Every confirmed or discarded vector in the matrix maps to a finding or a documented negative.