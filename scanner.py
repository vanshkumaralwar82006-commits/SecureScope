from urllib.parse import urlparse
import html
import requests
import pandas as pd

TIMEOUT_SECONDS = 8
USER_AGENT = "SecureScope-Educational-Auditor/1.0"

def _normalize_url(raw_url: str) -> str:
    if not raw_url or not raw_url.strip():
        raise ValueError("Enter a website URL first.")
    value = raw_url.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not look valid. Example: https://example.com")
    if parsed.username or parsed.password:
        raise ValueError("Do not include usernames or passwords in a URL.")
    return value

def _finding(title, severity, evidence, recommendation):
    return {"Finding": title, "Severity": severity, "Evidence": evidence, "Recommendation": recommendation}

def scan_website(raw_url: str) -> dict:
    url = _normalize_url(raw_url)
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS,
                                allow_redirects=True, stream=False)
    except requests.exceptions.SSLError:
        raise ValueError("TLS/SSL connection failed. Check the URL and certificate; no result was scored.")
    except requests.exceptions.Timeout:
        raise ValueError(f"The request timed out after {TIMEOUT_SECONDS} seconds. Try again or use an authorized test site.")
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Could not request that website: {exc.__class__.__name__}. Check the URL and network.")

    final_url = response.url
    parsed_final = urlparse(final_url)
    response_headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    recommendations = []

    if parsed_final.scheme != "https":
        findings.append(_finding("HTTPS not used after redirects", "High",
            f"Final URL scheme is {parsed_final.scheme.upper()}.",
            "Serve the site over HTTPS and redirect HTTP requests to HTTPS."))
        recommendations.append("Enable HTTPS and redirect HTTP traffic to HTTPS.")
    else:
        findings.append(_finding("HTTPS is used", "Info", "Final URL uses HTTPS.",
            "Keep TLS certificates valid and maintain modern TLS settings."))

    checks = [
        ("strict-transport-security", "Strict-Transport-Security (HSTS)", "Medium",
         "For HTTPS sites, consider a suitable HSTS policy after confirming all subdomains are ready.",
         "Header was not observed in the response."),
        ("content-security-policy", "Content-Security-Policy (CSP)", "Medium",
         "Define a CSP suited to the site's resources; test it before enforcing broadly.",
         "Header was not observed in the response."),
        ("x-content-type-options", "X-Content-Type-Options", "Low",
         "Set X-Content-Type-Options: nosniff where appropriate.",
         "Header was not observed in the response."),
        ("referrer-policy", "Referrer-Policy", "Low",
         "Set an intentional Referrer-Policy, for example strict-origin-when-cross-origin.",
         "Header was not observed in the response."),
        ("permissions-policy", "Permissions-Policy", "Low",
         "Review whether browser features should be restricted with Permissions-Policy.",
         "Header was not observed in the response."),
        ("x-frame-options", "Clickjacking protection header", "Low",
         "Use CSP frame-ancestors and/or X-Frame-Options according to compatibility needs.",
         "Neither X-Frame-Options nor CSP frame-ancestors was detected by this basic check."),
    ]
    csp = response_headers.get("content-security-policy", "").lower()
    for key, label, severity, recommendation, missing_text in checks:
        present = bool(response_headers.get(key))
        if key == "x-frame-options":
            present = present or ("frame-ancestors" in csp)
        if present:
            findings.append(_finding(f"{label} observed", "Info",
                "A related response header was present. This tool does not validate the policy's quality.",
                "Review the policy periodically and test it against the application's requirements."))
        else:
            findings.append(_finding(f"{label} missing or not detected", severity, missing_text, recommendation))
            recommendations.append(recommendation)

    # Basic, non-exploitative CORS observation. The result alone is not proof of a vulnerability.
    origin_test = "https://securescope.invalid"
    try:
        cors_response = requests.get(final_url, headers={**headers, "Origin": origin_test},
                                     timeout=TIMEOUT_SECONDS, allow_redirects=True, stream=False)
        acao = cors_response.headers.get("Access-Control-Allow-Origin", "")
        acac = cors_response.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == origin_test and acac == "true":
            findings.append(_finding("CORS reflects test Origin with credentials", "Medium",
                "The response reflected a test Origin and included Access-Control-Allow-Credentials: true.",
                "Review the CORS allowlist and ensure only trusted origins are permitted. Confirm impact in the application context."))
            recommendations.append("Review CORS origin allowlists and credentialed cross-origin access.")
        elif acao == origin_test:
            findings.append(_finding("CORS reflects test Origin", "Low",
                "The response reflected a test Origin. Reflection alone does not prove exploitability.",
                "Confirm whether dynamic origin reflection is intended and whether sensitive resources are exposed."))
            recommendations.append("Review dynamic CORS origin reflection and resource sensitivity.")
        elif acao == "*":
            findings.append(_finding("CORS wildcard observed", "Info",
                "Access-Control-Allow-Origin: * was observed. Wildcard behavior may be appropriate for public resources.",
                "Confirm that wildcard access is intentional and is not used for credentialed sensitive data."))
        else:
            findings.append(_finding("No test-Origin reflection observed", "Info",
                "The test Origin was not reflected in Access-Control-Allow-Origin.",
                "Review CORS policies against the application's intended origins; this single check is not comprehensive."))
    except requests.exceptions.RequestException:
        findings.append(_finding("CORS check not completed", "Info",
            "The secondary request did not complete.",
            "Review CORS manually or rerun when the authorized test site is reachable."))

    # Basic server banner note: avoid implying that a banner alone is a vulnerability.
    server = response_headers.get("server")
    if server:
        findings.append(_finding("Server response header disclosed", "Info",
            f"Server header observed: {server[:120]}",
            "Consider minimizing unnecessary version details in server banners, where practical."))

    deductions = {"High": 25, "Medium": 12, "Low": 5, "Info": 0}
    score = max(0, 100 - sum(deductions.get(x["Severity"], 0) for x in findings))
    if any(x["Severity"] == "High" for x in findings):
        risk = "High"
    elif any(x["Severity"] == "Medium" for x in findings):
        risk = "Moderate"
    elif any(x["Severity"] == "Low" for x in findings):
        risk = "Low"
    else:
        risk = "Informational"

    if not recommendations:
        recommendations = ["No recommendations were generated by these limited checks. Continue routine security reviews."]
    return {
        "requested_url": url,
        "final_url": final_url,
        "status_code": response.status_code,
        "score": score,
        "risk": risk,
        "findings": findings,
        "recommendations": list(dict.fromkeys(recommendations)),
        "checked_at": pd.Timestamp.now(tz="UTC").strftime("%Y-%m-%d %H:%M UTC"),
        "note": "Educational snapshot only; not a comprehensive security assessment."
    }

def findings_to_dataframe(findings):
    return pd.DataFrame(findings, columns=["Finding", "Severity", "Evidence", "Recommendation"])

def make_html_report(result):
    rows = []
    for item in result["findings"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(item.get(k, '')))}</td>"
                     for k in ["Finding", "Severity", "Evidence", "Recommendation"]) + "</tr>")
    safe_url = html.escape(result["final_url"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureScope Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1100px;margin:32px auto;padding:0 18px;color:#17263b}}
header{{background:#10243d;color:white;padding:24px;border-radius:14px}}
table{{border-collapse:collapse;width:100%;margin-top:20px}}th,td{{border:1px solid #d6deea;padding:10px;text-align:left;vertical-align:top}}
th{{background:#eaf0f8}}.note{{background:#fff5d6;padding:14px;border-radius:8px}}
</style></head><body>
<header><h1>SecureScope</h1><p>Automated Web Security Scanner — Educational Report</p></header>
<h2>Summary</h2><p><b>Target:</b> {safe_url}</p>
<p><b>Checked:</b> {html.escape(result["checked_at"])} | <b>HTTP status:</b> {result["status_code"]}</p>
<p><b>Score:</b> {result["score"]}/100 | <b>Risk category:</b> {html.escape(result["risk"])}</p>
<div class="note"><b>Important:</b> This limited check is not proof that a site is safe or vulnerable. Interpret findings in context.</div>
<h2>Findings</h2><table><thead><tr><th>Finding</th><th>Severity</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Recommendations</h2><ul>{''.join('<li>'+html.escape(x)+'</li>' for x in result["recommendations"])}</ul>
<p>Generated by SecureScope educational prototype.</p></body></html>"""
