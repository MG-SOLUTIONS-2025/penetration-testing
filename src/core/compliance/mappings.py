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
    # Auth/session
    307: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["8.3.4"],
        "nist_800_53": ["AC-7"],
        "cis": ["4.9"],
    },
    613: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["8.2.4"],
        "nist_800_53": ["AC-12"],
        "cis": ["4.3"],
    },
    620: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["8.3.6"],
        "nist_800_53": ["IA-5"],
        "cis": ["5.3"],
    },
    798: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["2.2.7"],
        "nist_800_53": ["IA-5"],
        "cis": ["3.11"],
    },
    640: {
        "owasp_top10_2021": ["A07:2021 - Identification and Authentication Failures"],
        "pci_dss_4": ["8.3.7"],
        "nist_800_53": ["IA-5"],
        "cis": ["5.2"],
    },
    # Injection (extended)
    77: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    78: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    90: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    91: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    94: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    643: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    917: {
        "owasp_top10_2021": ["A03:2021 - Injection"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-10"],
        "cis": ["18.3"],
    },
    # Crypto
    326: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["4.2.1"],
        "nist_800_53": ["SC-13"],
        "cis": ["3.10"],
    },
    327: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["4.2.1"],
        "nist_800_53": ["SC-13"],
        "cis": ["3.10"],
    },
    328: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["8.3.2"],
        "nist_800_53": ["IA-5", "SC-13"],
        "cis": ["3.11"],
    },
    330: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-13"],
        "cis": ["3.10"],
    },
    338: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-13"],
        "cis": ["3.10"],
    },
    347: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["4.2.1"],
        "nist_800_53": ["SC-8"],
        "cis": ["3.10"],
    },
    # Access control
    22: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    23: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    36: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    285: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    639: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    862: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
    863: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3", "AC-6"],
        "cis": ["3.3"],
    },
    # Info disclosure
    200: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["3.3"],
        "nist_800_53": ["SC-8", "SI-12"],
        "cis": ["3.1"],
    },
    209: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SI-11"],
        "cis": ["4.9"],
    },
    532: {
        "owasp_top10_2021": ["A09:2021 - Security Logging and Monitoring Failures"],
        "pci_dss_4": ["10.3"],
        "nist_800_53": ["AU-9"],
        "cis": ["8.3"],
    },
    # Resource
    400: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-5"],
        "cis": ["12.3"],
    },
    770: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-5"],
        "cis": ["12.3"],
    },
    776: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-5"],
        "cis": [],
    },
    # Config
    319: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["4.2.1"],
        "nist_800_53": ["SC-8"],
        "cis": ["3.10"],
    },
    614: {
        "owasp_top10_2021": ["A02:2021 - Cryptographic Failures"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-8"],
        "cis": ["4.8"],
    },
    1004: {
        "owasp_top10_2021": ["A05:2021 - Security Misconfiguration"],
        "pci_dss_4": ["6.2.4"],
        "nist_800_53": ["SC-8"],
        "cis": ["4.8"],
    },
    732: {
        "owasp_top10_2021": ["A01:2021 - Broken Access Control"],
        "pci_dss_4": ["7.2"],
        "nist_800_53": ["AC-3"],
        "cis": ["3.3"],
    },
}

FRAMEWORKS = ["owasp_top10_2021", "pci_dss_4", "nist_800_53", "cis"]
