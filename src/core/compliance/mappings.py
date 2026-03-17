"""Static CWE → compliance framework mappings."""

# CWE ID → list of framework references
CWE_FRAMEWORK_MAP: dict[int, dict[str, list[str]]] = {
    # Injection
    79: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    89: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    # Broken Auth
    287: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["8.3"],
        "nist_800_53": ["IA-2", "IA-5"],
        "cis": ["4.1", "4.2"],
    },
    # Sensitive Data Exposure
    311: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["4.2"],
        "nist_800_53": ["SC-8", "SC-28"],
        "cis": ["3.7"],
    },
    # XXE
    611: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": [],
    },
    # Broken Access Control
    284: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    # Security Misconfiguration
    16: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["2.2"],
        "nist_800_53": ["CM-6"],
        "cis": ["4.1"],
    },
    # CSRF
    352: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": [],
    },
    # Using Components with Known Vulns
    1035: {
        "owasp_top10_2021": ["A06:2021 - Vulnerable and Outdated Components"],
        "pci_dss_4": ["6.3.2"],
        "nist_800_53": ["RA-5", "SI-2"],
        "cis": ["2.1"],
    },
    # SSRF
    918: {
        "owasp_top10_2021": ["A10:2021 - Server-Side Request Forgery"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": [],
    },
    # Insecure Deserialization
    502: {
        "owasp_top10_2021": ["A08:2021 - Software and Data Integrity Failures"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": [],
    },
}

FRAMEWORKS = ["owasp_top10_2021", "pci_dss_4", "nist_800_53", "cis"]
