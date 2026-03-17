import hashlib

import httpx

HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "expected_contains": "max-age=",
        "description": "HSTS not configured; browsers may allow HTTP connections",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "expected_contains": None,  # just needs to exist
        "description": "No CSP header; XSS attacks are more likely to succeed",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "expected_value": "nosniff",
        "description": "Missing nosniff; MIME-type sniffing may lead to XSS",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "expected_in": ["DENY", "SAMEORIGIN"],
        "description": "Missing X-Frame-Options; clickjacking may be possible",
    },
    "Referrer-Policy": {
        "severity": "low",
        "expected_contains": None,
        "description": "No Referrer-Policy; sensitive URLs may leak in referrer headers",
    },
    "Permissions-Policy": {
        "severity": "low",
        "expected_contains": None,
        "description": "No Permissions-Policy; browser features not explicitly restricted",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "expected_contains": None,
        "description": "No COOP header; cross-origin isolation not enforced",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "expected_contains": None,
        "description": "No CORP header; resources may be loaded cross-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "low",
        "expected_contains": None,
        "description": "No COEP header; cross-origin isolation incomplete",
    },
}

DEPRECATED_HEADERS = {
    "X-XSS-Protection": ("X-XSS-Protection is deprecated and can introduce vulnerabilities"),
}


def check_headers(url: str) -> list[dict]:
    findings = []

    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15.0, verify=False)
    except httpx.RequestError as e:
        return [
            {
                "title": f"Failed to connect to {url}",
                "severity": "info",
                "finding_type": "connection_error",
                "target_value": url,
                "detail": {"error": str(e)},
                "fingerprint": hashlib.sha256(f"conn_error|{url}".encode()).hexdigest(),
            }
        ]

    headers = resp.headers

    for header_name, check in HEADER_CHECKS.items():
        value = headers.get(header_name)

        if value is None:
            fp = hashlib.sha256(f"missing_header|{url}|{header_name}".encode()).hexdigest()
            findings.append(
                {
                    "title": f"Missing {header_name} header on {url}",
                    "severity": check["severity"],
                    "finding_type": "missing_header",
                    "target_value": url,
                    "detail": {
                        "header": header_name,
                        "description": check["description"],
                    },
                    "fingerprint": fp,
                }
            )
            continue

        # Check expected value
        if "expected_value" in check and value.lower() != check["expected_value"].lower():
            fp = hashlib.sha256(f"bad_header|{url}|{header_name}".encode()).hexdigest()
            findings.append(
                {
                    "title": f"Misconfigured {header_name} on {url}",
                    "severity": check["severity"],
                    "finding_type": "misconfigured_header",
                    "target_value": url,
                    "detail": {
                        "header": header_name,
                        "value": value,
                        "expected": check["expected_value"],
                    },
                    "fingerprint": fp,
                }
            )

        expected_in = check.get("expected_in", [])
        if expected_in and value.upper() not in [v.upper() for v in expected_in]:
            fp = hashlib.sha256(f"bad_header|{url}|{header_name}".encode()).hexdigest()
            findings.append(
                {
                    "title": f"Misconfigured {header_name} on {url}",
                    "severity": check["severity"],
                    "finding_type": "misconfigured_header",
                    "target_value": url,
                    "detail": {
                        "header": header_name,
                        "value": value,
                        "expected_one_of": check["expected_in"],
                    },
                    "fingerprint": fp,
                }
            )

        if "expected_contains" in check and check["expected_contains"] is not None:
            if check["expected_contains"].lower() not in value.lower():
                fp = hashlib.sha256(f"bad_header|{url}|{header_name}".encode()).hexdigest()
                findings.append(
                    {
                        "title": f"Misconfigured {header_name} on {url}",
                        "severity": check["severity"],
                        "finding_type": "misconfigured_header",
                        "target_value": url,
                        "detail": {
                            "header": header_name,
                            "value": value,
                            "expected_contains": check["expected_contains"],
                        },
                        "fingerprint": fp,
                    }
                )

    # Check for deprecated headers
    for header_name, warning in DEPRECATED_HEADERS.items():
        if headers.get(header_name):
            fp = hashlib.sha256(f"deprecated_header|{url}|{header_name}".encode()).hexdigest()
            findings.append(
                {
                    "title": f"Deprecated header {header_name} present on {url}",
                    "severity": "info",
                    "finding_type": "deprecated_header",
                    "target_value": url,
                    "detail": {
                        "header": header_name,
                        "value": headers.get(header_name),
                        "warning": warning,
                    },
                    "fingerprint": fp,
                }
            )

    # If no issues, add a positive finding
    if not findings:
        fp = hashlib.sha256(f"headers_ok|{url}".encode()).hexdigest()
        findings.append(
            {
                "title": f"All security headers properly configured on {url}",
                "severity": "info",
                "finding_type": "headers_pass",
                "target_value": url,
                "detail": {"checked_headers": list(HEADER_CHECKS.keys())},
                "fingerprint": fp,
            }
        )

    return findings
