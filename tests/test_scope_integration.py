"""Integration tests for scope URL parsing fixes."""

import pytest
from src.core.scope import _extract_host


def test_extract_host_with_scheme_and_path():
    """URL with scheme and path returns hostname only."""
    assert _extract_host("http://example.com/path") == "example.com"


def test_extract_host_with_scheme_https():
    assert _extract_host("https://example.com/some/path?q=1") == "example.com"


def test_extract_host_with_port_no_scheme():
    """Host:port without scheme strips port."""
    assert _extract_host("example.com:8080") == "example.com"


def test_extract_host_plain_domain():
    """Plain domain without port or scheme returned as-is."""
    assert _extract_host("example.com") == "example.com"


def test_extract_host_ipv6_literal():
    """IPv6 literals with brackets are not stripped."""
    result = _extract_host("https://[::1]:443/")
    assert result == "::1"


def test_extract_host_ipv6_bare():
    """Bare IPv6 address (no brackets) is preserved."""
    assert _extract_host("[::1]") == "[::1]"


def test_extract_host_ip_with_port():
    """IP with port strips port."""
    assert _extract_host("192.168.1.1:8080") == "192.168.1.1"


def test_extract_host_plain_ip():
    """Plain IP without port returned as-is."""
    assert _extract_host("192.168.1.1") == "192.168.1.1"
