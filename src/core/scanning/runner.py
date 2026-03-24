import subprocess

ALLOWED_IMAGES: frozenset[str] = frozenset(
    {
        "instrumentisto/nmap",
        "projectdiscovery/subfinder",
        "projectdiscovery/nuclei",
        "caffix/amass",
        "adguard/masscan",
        "sullo/nikto",
        "ghcr.io/ffuf/ffuf",
        "sqlmapproject/sqlmap",
        "wpscanteam/wpscan",
        "zaproxy/zap-stable",
        "grafana/k6",
    }
)


class ImageNotAllowedError(ValueError):
    pass


class ToolRunner:
    def run_in_container(
        self,
        image: str,
        command: list[str],
        timeout: int = 300,
        network: str = "host",
        memory: str = "1g",
        cpus: str = "1.0",
    ) -> subprocess.CompletedProcess:
        if image not in ALLOWED_IMAGES:
            raise ImageNotAllowedError(f"Image not allowed: {image}")

        docker_cmd = [
            "docker",
            "run",
            "--rm",
            f"--network={network}",
            f"--memory={memory}",
            f"--cpus={cpus}",
            "--no-new-privileges",
            "--cap-drop=ALL",
            "--pids-limit=256",
            "--read-only",
            image,
            *command,
        ]
        return subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
