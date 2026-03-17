"""Metasploit RPC client wrapper."""


class MetasploitClient:
    def __init__(self, host: str = "msfrpcd", port: int = 55553, password: str = ""):
        self.host = host
        self.port = port
        self.password = password
        self._client = None

    def connect(self):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            self._client = MsfRpcClient(self.password, server=self.host, port=self.port)
        except ImportError:
            raise RuntimeError("pymetasploit3 is required for Metasploit integration")

    @property
    def client(self):
        if self._client is None:
            self.connect()
        return self._client

    def list_exploits(self, search: str = "") -> list[str]:
        modules = self.client.modules.exploits
        if search:
            return [m for m in modules if search.lower() in m.lower()]
        return list(modules)

    def run_exploit(
        self,
        module_name: str,
        options: dict,
    ) -> dict:
        exploit = self.client.modules.use("exploit", module_name)
        for key, value in options.items():
            exploit[key] = value

        result = exploit.execute()
        return {
            "job_id": result.get("job_id"),
            "uuid": result.get("uuid"),
        }

    def get_sessions(self) -> dict:
        return dict(self.client.sessions.list)
