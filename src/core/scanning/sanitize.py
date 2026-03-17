"""Input sanitization for scanning commands — prevents command injection."""

import ipaddress
import re
from urllib.parse import urlparse

# --- Target validation ---

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
_PORTS_RE = re.compile(r"^[\d,-]+$")
_TEMPLATE_RE = re.compile(r"^[a-zA-Z0-9/_.-]+$")

VALID_TARGET_TYPES = frozenset({"domain", "ip", "cidr", "url"})

ALLOWED_NMAP_FLAGS = frozenset(
    {
        "-sV",
        "-sC",
        "-sS",
        "-sT",
        "-sU",
        "-sN",
        "-sF",
        "-sX",
        "-sA",
        "-sP",
        "-sn",
        "-Pn",
        "-PE",
        "-PS",
        "-PA",
        "-PU",
        "-A",
        "-O",
        "-T0",
        "-T1",
        "-T2",
        "-T3",
        "-T4",
        "-T5",
        "-v",
        "-vv",
        "--open",
        "--top-ports",
        "--script=vuln",
        "--script=default",
        "--script=safe",
        "--version-intensity",
        "-oX",
        "-oN",
        "-oG",
    }
)

VALID_NUCLEI_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})


class SanitizationError(ValueError):
    """Raised when input fails sanitization."""


def validate_target_value(value: str, target_type: str) -> str:
    if not value or not value.strip():
        raise SanitizationError("Target value cannot be empty")

    value = value.strip()

    if "\x00" in value:
        raise SanitizationError("Target value contains null bytes")

    if target_type not in VALID_TARGET_TYPES:
        raise SanitizationError(f"Invalid target type: {target_type}")

    if target_type == "domain":
        if not _DOMAIN_RE.match(value):
            raise SanitizationError(f"Invalid domain: {value}")
        if ".." in value:
            raise SanitizationError(f"Invalid domain (path traversal): {value}")
        return value

    if target_type == "ip":
        try:
            addr = ipaddress.ip_address(value)
            return str(addr)
        except ValueError:
            raise SanitizationError(f"Invalid IP address: {value}")

    if target_type == "cidr":
        try:
            network = ipaddress.ip_network(value, strict=False)
            return str(network)
        except ValueError:
            raise SanitizationError(f"Invalid CIDR: {value}")

    if target_type == "url":
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise SanitizationError(f"Invalid URL scheme: {parsed.scheme}")
        if not parsed.hostname:
            raise SanitizationError(f"URL missing hostname: {value}")
        hostname = parsed.hostname
        if not _DOMAIN_RE.match(hostname):
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                raise SanitizationError(f"Invalid URL hostname: {hostname}")
        return value

    raise SanitizationError(f"Unhandled target type: {target_type}")


def validate_ports(ports: str) -> str:
    if not ports or not ports.strip():
        raise SanitizationError("Ports cannot be empty")

    ports = ports.strip()
    if not _PORTS_RE.match(ports):
        raise SanitizationError(f"Invalid port specification: {ports}")
    return ports


def validate_nmap_args(args: str) -> list[str]:
    if not args or not args.strip():
        return []

    tokens = args.strip().split()
    validated = []
    for token in tokens:
        # Allow flags that are in the allowlist
        flag_base = token.split("=")[0] if "=" in token else token
        if flag_base in ALLOWED_NMAP_FLAGS:
            validated.append(token)
        elif token.lstrip("-").isdigit():
            # Allow numeric arguments (e.g. for --top-ports 1000)
            validated.append(token)
        else:
            raise SanitizationError(f"Disallowed nmap argument: {token}")

    return validated


def validate_nuclei_severity(severity: str) -> str:
    if not severity or not severity.strip():
        raise SanitizationError("Severity cannot be empty")

    parts = [s.strip().lower() for s in severity.split(",")]
    for part in parts:
        if part not in VALID_NUCLEI_SEVERITIES:
            raise SanitizationError(f"Invalid nuclei severity: {part}")

    return ",".join(parts)


def validate_nuclei_templates(templates: str) -> str:
    if not templates or not templates.strip():
        return ""

    templates = templates.strip()
    if ".." in templates:
        raise SanitizationError(f"Path traversal in template: {templates}")

    if not _TEMPLATE_RE.match(templates):
        raise SanitizationError(f"Invalid nuclei template: {templates}")

    return templates
