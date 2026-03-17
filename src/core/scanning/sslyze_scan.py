import hashlib


def run_sslyze_scan(hostname: str, port: int = 443) -> list[dict]:
    from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
    from sslyze.plugins.scan_commands import ScanCommand

    server = ServerNetworkLocation(hostname, port)
    scanner = Scanner()
    scanner.queue_scans(
        [
            ServerScanRequest(
                server,
                {
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.HTTP_HEADERS,
                },
            )
        ]
    )

    findings = []
    for result in scanner.get_results():
        scan = result.scan_result
        if scan is None:
            continue

        # Check deprecated protocols
        deprecated = {
            "SSL 2.0": scan.ssl_2_0_cipher_suites,
            "SSL 3.0": scan.ssl_3_0_cipher_suites,
            "TLS 1.0": scan.tls_1_0_cipher_suites,
            "TLS 1.1": scan.tls_1_1_cipher_suites,
        }
        for proto_name, proto_result in deprecated.items():
            if proto_result and proto_result.result:
                accepted = proto_result.result.accepted_cipher_suites
                if accepted:
                    cipher_names = [c.cipher_suite.name for c in accepted]
                    fp_data = f"tls_deprecated|{hostname}|{proto_name}"
                    fp = hashlib.sha256(fp_data.encode()).hexdigest()
                    findings.append(
                        {
                            "title": f"Deprecated protocol {proto_name} supported on {hostname}:{port}",
                            "severity": "high",
                            "finding_type": "tls_issue",
                            "target_value": f"{hostname}:{port}",
                            "detail": {
                                "protocol": proto_name,
                                "accepted_ciphers": cipher_names,
                            },
                            "fingerprint": fp,
                        }
                    )

        # Check Heartbleed
        if scan.heartbleed and scan.heartbleed.result:
            if scan.heartbleed.result.is_vulnerable_to_heartbleed:
                fp = hashlib.sha256(f"heartbleed|{hostname}".encode()).hexdigest()
                findings.append(
                    {
                        "title": f"Heartbleed vulnerability on {hostname}:{port}",
                        "severity": "critical",
                        "finding_type": "tls_issue",
                        "target_value": f"{hostname}:{port}",
                        "detail": {"vulnerability": "heartbleed"},
                        "fingerprint": fp,
                    }
                )

        # Check certificate info
        if scan.certificate_info and scan.certificate_info.result:
            for deployment in scan.certificate_info.result.certificate_deployments:
                leaf = deployment.received_certificate_chain[0]
                from datetime import UTC, datetime

                now = datetime.now(UTC)
                delta = leaf.not_valid_after_utc - now
                days_to_expiry = delta.days
                if days_to_expiry < 30:
                    severity = "critical" if days_to_expiry < 0 else "high"
                    fp_data = f"cert_expiry|{hostname}"
                    fp = hashlib.sha256(fp_data.encode()).hexdigest()
                    expired = days_to_expiry < 0
                    label = "expired" if expired else "expiring soon"
                    findings.append(
                        {
                            "title": f"Certificate {label} on {hostname}:{port}",
                            "severity": severity,
                            "finding_type": "tls_issue",
                            "target_value": f"{hostname}:{port}",
                            "detail": {
                                "days_to_expiry": days_to_expiry,
                                "not_valid_after": str(leaf.not_valid_after_utc),
                                "subject": str(leaf.subject),
                            },
                            "fingerprint": fp,
                        }
                    )

        # Check HSTS
        if scan.http_headers and scan.http_headers.result:
            if scan.http_headers.result.strict_transport_security_header is None:
                fp = hashlib.sha256(f"hsts_missing|{hostname}".encode()).hexdigest()
                findings.append(
                    {
                        "title": f"Missing HSTS header on {hostname}:{port}",
                        "severity": "medium",
                        "finding_type": "missing_header",
                        "target_value": f"{hostname}:{port}",
                        "detail": {"header": "Strict-Transport-Security"},
                        "fingerprint": fp,
                    }
                )

    return findings
