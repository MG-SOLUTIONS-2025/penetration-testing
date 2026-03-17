import pytest

from src.core.scanning.sanitize import (
    SanitizationError,
    validate_nmap_args,
    validate_nuclei_severity,
    validate_nuclei_templates,
    validate_ports,
    validate_target_value,
)


class TestValidateTargetValue:
    def test_valid_domain(self):
        assert validate_target_value("example.com", "domain") == "example.com"
        assert validate_target_value("sub.example.com", "domain") == "sub.example.com"
        assert validate_target_value("test-site.co.uk", "domain") == "test-site.co.uk"

    def test_valid_ip(self):
        assert validate_target_value("192.168.1.1", "ip") == "192.168.1.1"
        assert validate_target_value("10.0.0.1", "ip") == "10.0.0.1"
        assert validate_target_value("::1", "ip") == "::1"

    def test_valid_cidr(self):
        assert validate_target_value("192.168.1.0/24", "cidr") == "192.168.1.0/24"
        assert validate_target_value("10.0.0.0/8", "cidr") == "10.0.0.0/8"

    def test_valid_url(self):
        assert validate_target_value("https://example.com", "url") == "https://example.com"
        assert (
            validate_target_value("http://192.168.1.1:8080/path", "url")
            == "http://192.168.1.1:8080/path"
        )

    # --- Injection attempts ---

    def test_rejects_semicolon_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com; rm -rf /", "domain")

    def test_rejects_pipe_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com | cat /etc/passwd", "domain")

    def test_rejects_subshell_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("$(whoami).example.com", "domain")

    def test_rejects_backtick_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("`id`.example.com", "domain")

    def test_rejects_null_bytes(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com\x00", "domain")

    def test_rejects_path_traversal_in_domain(self):
        with pytest.raises(SanitizationError):
            validate_target_value("../../../etc/passwd", "domain")

    def test_rejects_invalid_ip(self):
        with pytest.raises(SanitizationError):
            validate_target_value("999.999.999.999", "ip")

    def test_rejects_ip_with_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("192.168.1.1; whoami", "ip")

    def test_rejects_invalid_cidr(self):
        with pytest.raises(SanitizationError):
            validate_target_value("not-a-cidr", "cidr")

    def test_rejects_url_with_bad_scheme(self):
        with pytest.raises(SanitizationError):
            validate_target_value("file:///etc/passwd", "url")

    def test_rejects_empty_value(self):
        with pytest.raises(SanitizationError):
            validate_target_value("", "domain")

    def test_rejects_invalid_target_type(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com", "invalid")

    def test_rejects_newline_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com\nmalicious", "domain")

    def test_rejects_ampersand_injection(self):
        with pytest.raises(SanitizationError):
            validate_target_value("example.com && whoami", "domain")


class TestValidatePorts:
    def test_valid_ports(self):
        assert validate_ports("80") == "80"
        assert validate_ports("80,443") == "80,443"
        assert validate_ports("1-1000") == "1-1000"
        assert validate_ports("22,80,443,8080-8090") == "22,80,443,8080-8090"

    def test_rejects_injection_in_ports(self):
        with pytest.raises(SanitizationError):
            validate_ports("80; whoami")

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_ports("")

    def test_rejects_letters(self):
        with pytest.raises(SanitizationError):
            validate_ports("abc")


class TestValidateNmapArgs:
    def test_valid_flags(self):
        assert validate_nmap_args("-sV -sC") == ["-sV", "-sC"]
        assert validate_nmap_args("-A -T4") == ["-A", "-T4"]

    def test_empty_returns_empty(self):
        assert validate_nmap_args("") == []

    def test_rejects_dangerous_flags(self):
        with pytest.raises(SanitizationError):
            validate_nmap_args("--script=exploit")

    def test_rejects_output_redirect(self):
        with pytest.raises(SanitizationError):
            validate_nmap_args("-oN /tmp/output")

    def test_rejects_arbitrary_args(self):
        with pytest.raises(SanitizationError):
            validate_nmap_args("--datadir=/etc")


class TestValidateNucleiSeverity:
    def test_valid_severities(self):
        assert validate_nuclei_severity("critical,high") == "critical,high"
        assert validate_nuclei_severity("low") == "low"

    def test_rejects_invalid_severity(self):
        with pytest.raises(SanitizationError):
            validate_nuclei_severity("critical; whoami")

    def test_rejects_empty(self):
        with pytest.raises(SanitizationError):
            validate_nuclei_severity("")


class TestValidateNucleiTemplates:
    def test_valid_templates(self):
        assert validate_nuclei_templates("cves/2021") == "cves/2021"
        assert validate_nuclei_templates("tech-detect") == "tech-detect"

    def test_rejects_path_traversal(self):
        with pytest.raises(SanitizationError):
            validate_nuclei_templates("../../etc/passwd")

    def test_rejects_special_chars(self):
        with pytest.raises(SanitizationError):
            validate_nuclei_templates("template; whoami")

    def test_empty_returns_empty(self):
        assert validate_nuclei_templates("") == ""
