import shlex
import subprocess


class ToolRunner:
    def run_in_container(
        self,
        image: str,
        command: str,
        timeout: int = 300,
        network: str = "host",
        memory: str = "1g",
        cpus: str = "1.0",
    ) -> subprocess.CompletedProcess:
        safe_cmd = shlex.split(command)
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            f"--network={network}",
            f"--memory={memory}",
            f"--cpus={cpus}",
            image,
            *safe_cmd,
        ]
        return subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
