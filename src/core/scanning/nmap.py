import hashlib
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_str: str, engagement_id: str) -> list[dict]:
    findings = []
    root = ET.fromstring(xml_str)

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr", "unknown")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            protocol = port.get("protocol", "tcp")
            portid = port.get("portid", "0")
            service_el = port.find("service")
            if service_el is not None:
                service_name = service_el.get("name", "unknown")
                service_product = service_el.get("product", "")
                service_version = service_el.get("version", "")
            else:
                service_name, service_product, service_version = "unknown", "", ""

            title = f"Open port {portid}/{protocol} - {service_name}"
            if service_product:
                title += f" ({service_product}"
                if service_version:
                    title += f" {service_version}"
                title += ")"

            fp_input = f"open_port|{addr}|{portid}/{protocol}|{service_name}"
            fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

            findings.append(
                {
                    "engagement_id": engagement_id,
                    "title": title,
                    "severity": "info",
                    "finding_type": "open_port",
                    "target_value": addr,
                    "detail": {
                        "port": int(portid),
                        "protocol": protocol,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                    },
                    "fingerprint": fingerprint,
                }
            )

        # Parse NSE script output for vulnerabilities
        for port in ports_el.findall("port"):
            for script in port.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                if "VULNERABLE" in script_output.upper():
                    portid = port.get("portid", "0")
                    fp_input = f"vuln|{addr}|{portid}|{script_id}"
                    fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

                    findings.append(
                        {
                            "engagement_id": engagement_id,
                            "title": f"Vulnerability: {script_id} on {addr}:{portid}",
                            "severity": "high",
                            "finding_type": "vuln",
                            "target_value": addr,
                            "detail": {
                                "script_id": script_id,
                                "port": int(portid),
                                "output": script_output[:2000],
                            },
                            "raw_output": script_output[:5000],
                            "fingerprint": fingerprint,
                        }
                    )

    return findings
