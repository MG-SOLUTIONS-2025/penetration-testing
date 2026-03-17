from unittest.mock import MagicMock

from src.core.scope import _is_ip_in_cidr, _is_subdomain_of, target_matches_scope


class TestSubdomainCheck:
    def test_exact_match(self):
        assert _is_subdomain_of("example.com", "example.com")

    def test_subdomain_matches(self):
        assert _is_subdomain_of("api.example.com", "example.com")
        assert _is_subdomain_of("deep.sub.example.com", "example.com")

    def test_different_domain_no_match(self):
        assert not _is_subdomain_of("evil.com", "example.com")
        assert not _is_subdomain_of("notexample.com", "example.com")

    def test_trailing_dots(self):
        assert _is_subdomain_of("api.example.com.", "example.com.")


class TestCidrCheck:
    def test_ip_in_range(self):
        assert _is_ip_in_cidr("192.168.1.5", "192.168.1.0/24")

    def test_ip_outside_range(self):
        assert not _is_ip_in_cidr("10.0.0.1", "192.168.1.0/24")

    def test_single_host(self):
        assert _is_ip_in_cidr("10.0.0.1", "10.0.0.1/32")

    def test_invalid_ip(self):
        assert not _is_ip_in_cidr("not-an-ip", "192.168.1.0/24")


class TestTargetMatchesScope:
    def _make_target(self, target_type, value):
        t = MagicMock()
        t.target_type = target_type
        t.value = value
        return t

    def test_domain_match(self):
        scope = self._make_target("domain", "example.com")
        assert target_matches_scope("sub.example.com", scope)
        assert target_matches_scope("example.com", scope)
        assert not target_matches_scope("evil.com", scope)

    def test_ip_match(self):
        scope = self._make_target("ip", "192.168.1.1")
        assert target_matches_scope("192.168.1.1", scope)
        assert not target_matches_scope("192.168.1.2", scope)

    def test_cidr_match(self):
        scope = self._make_target("cidr", "10.0.0.0/8")
        assert target_matches_scope("10.1.2.3", scope)
        assert not target_matches_scope("192.168.1.1", scope)

    def test_url_extracts_host(self):
        scope = self._make_target("domain", "example.com")
        assert target_matches_scope("https://api.example.com/path", scope)
