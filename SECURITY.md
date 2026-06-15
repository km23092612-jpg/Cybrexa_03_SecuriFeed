# Security Policy — SecuriFeed PhishDetect

## Reporting a Vulnerability
Email: `security@yourdomain.com` — do NOT open a public issue.

## Security Design

### Privacy First
- All URL analysis runs 100% in the browser — zero server calls
- No URLs are logged, stored, or transmitted
- No third-party analytics

### XSS Prevention
- All user content rendered via `textContent` — never `innerHTML`
- URL display in quiz uses `textContent` only
- No `eval()` anywhere in codebase

### Content Security Policy
Configured via `_headers` for Netlify deployment.

## Responsible Disclosure
Please give 48 hours to respond and 7 days to patch before public disclosure. 🛡️
