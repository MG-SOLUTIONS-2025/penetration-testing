from src.core.scanning.nmap import parse_nmap_xml
from src.core.scanning.nuclei import parse_nuclei_jsonl
from src.core.scanning.subfinder import parse_subfinder_jsonl


class TestNmapParser:
    def test_parses_open_ports(self, nmap_xml_output):
        findings = parse_nmap_xml(nmap_xml_output, "eng-123")
        open_ports = [f for f in findings if f["finding_type"] == "open_port"]
        assert len(open_ports) == 2
        assert open_ports[0]["target_value"] == "192.168.1.1"
        assert open_ports[0]["detail"]["port"] == 22
        assert open_ports[0]["detail"]["service"] == "ssh"
        assert open_ports[1]["detail"]["port"] == 80

    def test_ignores_closed_ports(self, nmap_xml_output):
        findings = parse_nmap_xml(nmap_xml_output, "eng-123")
        ports = [f["detail"]["port"] for f in findings if f["finding_type"] == "open_port"]
        assert 443 not in ports

    def test_sets_info_severity(self, nmap_xml_output):
        findings = parse_nmap_xml(nmap_xml_output, "eng-123")
        for f in findings:
            if f["finding_type"] == "open_port":
                assert f["severity"] == "info"

    def test_generates_unique_fingerprints(self, nmap_xml_output):
        findings = parse_nmap_xml(nmap_xml_output, "eng-123")
        fps = [f["fingerprint"] for f in findings]
        assert len(fps) == len(set(fps))


class TestNucleiParser:
    def test_parses_findings(self, nuclei_jsonl_output):
        findings = parse_nuclei_jsonl(nuclei_jsonl_output, "eng-123")
        assert len(findings) == 2

    def test_maps_severity(self, nuclei_jsonl_output):
        findings = parse_nuclei_jsonl(nuclei_jsonl_output, "eng-123")
        assert findings[0]["severity"] == "info"
        assert findings[1]["severity"] == "critical"

    def test_extracts_template_id(self, nuclei_jsonl_output):
        findings = parse_nuclei_jsonl(nuclei_jsonl_output, "eng-123")
        assert findings[1]["detail"]["template_id"] == "cve-2021-44228"


class TestSubfinderParser:
    def test_parses_subdomains(self, subfinder_jsonl_output):
        findings = parse_subfinder_jsonl(subfinder_jsonl_output, "eng-123")
        assert len(findings) == 3
        hosts = [f["target_value"] for f in findings]
        assert "api.example.com" in hosts
        assert "mail.example.com" in hosts

    def test_all_info_severity(self, subfinder_jsonl_output):
        findings = parse_subfinder_jsonl(subfinder_jsonl_output, "eng-123")
        for f in findings:
            assert f["severity"] == "info"
            assert f["finding_type"] == "subdomain"
