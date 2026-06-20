"""Security checks for API responses.
Each check returns a list of findings with: id, title, severity, description, evidence, remediation.
"""
import re
import urllib.parse
from difflib import SequenceMatcher

SENSITIVE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"-----BEGIN PRIVATE KEY-----"),
    re.compile(r"password\s*=\s*['\"]?\w+['\"]?", re.I),
    re.compile(r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_=]+['\"]?", re.I)
]


def _add(findings, id_, title, severity, description, evidence, remediation):
    findings.append({
        'id': id_,
        'title': title,
        'severity': severity,
        'description': description,
        'evidence': evidence,
        'remediation': remediation
    })


def check_security_headers(resp_headers):
    findings = []
    # List of important headers and why
    expected = {
        'Strict-Transport-Security': 'Enforces HTTPS; recommended for production HTTPS services',
        'X-Content-Type-Options': 'Prevents MIME-sniffing; should be "nosniff"',
        'X-Frame-Options': 'Mitigates clickjacking; use DENY or SAMEORIGIN',
        'Content-Security-Policy': 'Reduces XSS risks by controlling resources the page may load',
        'Referrer-Policy': 'Controls Referer header leakage',
    }
    for h, why in expected.items():
        if h not in resp_headers:
            _add(findings,
                 f"missing_header_{h}",
                 f"Missing security header: {h}",
                 'medium',
                 f"The response is missing the '{h}' header. {why}.",
                 '',
                 f"Set the {h} header with an appropriate value on the server (see OWASP Secure Headers).")
    return findings


def check_cors(url, resp_headers, session, timeout=10):
    findings = []
    acao = resp_headers.get('Access-Control-Allow-Origin')
    acac = resp_headers.get('Access-Control-Allow-Credentials')
    if acao:
        if acao.strip() == '*':
            if acac and acac.lower() == 'true':
                _add(findings, 'cors_wildcard_credentials', 'CORS allows credentials with wildcard origin', 'high',
                     'Access-Control-Allow-Origin is "*" and Access-Control-Allow-Credentials is true. This allows any origin to send authenticated requests to the API via browsers.',
                     f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                     'Avoid using "*" for Access-Control-Allow-Origin when Allow-Credentials is true; explicitly set allowed origins.')
        else:
            # check for reflected origin (insecurely echoing)
            try:
                parsed = urllib.parse.urlparse(url)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                if acao.strip() == origin:
                    _add(findings, 'cors_reflects_origin', 'CORS reflects origin', 'medium',
                         'The server is reflecting the request Origin header in Access-Control-Allow-Origin which can be risky if combined with insufficient origin validation.',
                         f"Access-Control-Allow-Origin: {acao}",
                         'Validate origins against an allowlist on the server and avoid reflecting the Origin header directly.')
            except Exception:
                pass
    return findings


def check_sensitive_leaks(text):
    findings = []
    for p in SENSITIVE_PATTERNS:
        m = p.search(text or '')
        if m:
            _add(findings, 'sensitive_data_leak', 'Sensitive data in response body', 'high',
                 'The response body appears to contain sensitive secrets or keys which should not be exposed.',
                 m.group(0)[:200],
                 'Remove keys from responses, rotate any compromised keys, and ensure secrets are not printed in error messages or responses.')
    return findings


def _similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


def check_reflection_and_injection(url, session, timeout=10):
    findings = []
    # If URL has query params, try simple injection tests
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if not qs:
        return findings

    # Build two altered queries
    sqli_payload = "' OR '1'='1"
    xss_payload = '<script>alert(1)</script>'

    base = parsed._replace(query='').geturl()
    # prepare original, sqli and xss responses
    try:
        orig = session.get(url, timeout=timeout)
        sqli_qs = {k: v + [sqli_payload] for k, v in qs.items()}
        xss_qs = {k: v + [xss_payload] for k, v in qs.items()}
        sqli_url = base + '?' + urllib.parse.urlencode({k: v[0] for k, v in sqli_qs.items()})
        xss_url = base + '?' + urllib.parse.urlencode({k: v[0] for k, v in xss_qs.items()})
        sqli_resp = session.get(sqli_url, timeout=timeout)
        xss_resp = session.get(xss_url, timeout=timeout)

        # crude sqli detection: large similarity to original or obvious SQL errors
        if any(e.lower() in sqli_resp.text.lower() for e in ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation mark']):
            _add(findings, 'sqli_error_messages', 'SQL error message reflected in response', 'high',
                 'The response contains database error text after an SQL injection payload.',
                 sqli_resp.text[:400],
                 'Sanitize and parameterize database queries; do not show database errors to users.')
        else:
            # compare lengths
            if abs(len(sqli_resp.text) - len(orig.text)) > 100:
                _add(findings, 'sqli_response_diff', 'Differing response for SQLi payload', 'medium',
                     'The response differs significantly when a typical SQL injection payload was sent; this can indicate vulnerability.',
                     f"orig_len={len(orig.text)} sqli_len={len(sqli_resp.text)}",
                     'Validate and parameterize inputs on server side; use prepared statements.')

        # XSS reflection: check if payload is in response
        if xss_payload in xss_resp.text:
            _add(findings, 'reflected_xss', 'Reflected XSS', 'high',
                 'A script payload injected into a parameter was reflected in the HTML response without sanitization.',
                 xss_payload,
                 'Sanitize user input before rendering; use context-sensitive encoding/escaping and CSP headers.')

    except Exception:
        pass
    return findings


def run_all_checks(url, session, timeout=10):
    findings = []
    # get a baseline response
    try:
        r = session.get(url, timeout=timeout)
        headers = r.headers
        body = r.text
    except Exception as e:
        return [{'id': 'request_failed', 'title': 'Request failed', 'severity': 'low', 'description': 'Could not fetch URL', 'evidence': str(e), 'remediation': 'Ensure the URL is accessible.'}]

    findings.extend(check_security_headers(headers))
    findings.extend(check_cors(url, headers, session, timeout=timeout))
    findings.extend(check_sensitive_leaks(body))
    findings.extend(check_reflection_and_injection(url, session, timeout=timeout))
    return findings
