import pytest


@pytest.fixture
def nmap_xml_output():
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.fixture
def nuclei_jsonl_output():
    return """{"template-id":"tech-detect","matched-at":"https://example.com","info":{"name":"Nginx Detection","severity":"info","tags":["tech"]},"type":"http"}
{"template-id":"cve-2021-44228","matched-at":"https://example.com:8080","info":{"name":"Log4j RCE","severity":"critical","description":"Remote code execution via Log4Shell","tags":["cve","rce"]},"type":"http","matcher-name":"log4j"}"""


@pytest.fixture
def subfinder_jsonl_output():
    return """{"host":"api.example.com","source":"crtsh"}
{"host":"mail.example.com","source":"virustotal"}
{"host":"dev.example.com","source":"securitytrails"}"""
