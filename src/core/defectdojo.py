import httpx

from src.core.config import settings


class DefectDojoClient:
    def __init__(
        self,
        base_url: str = settings.defectdojo_url,
        api_key: str = settings.defectdojo_api_key,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Accept": "application/json",
        }

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=30.0,
        )

    async def ensure_product(self, name: str) -> int:
        async with self._client() as client:
            resp = await client.get("/api/v2/products/", params={"name": name})
            resp.raise_for_status()
            results = resp.json().get("results", [])
            if results:
                return results[0]["id"]

            resp = await client.post(
                "/api/v2/products/",
                json={"name": name, "prod_type": 1, "description": f"PenTest Platform: {name}"},
            )
            resp.raise_for_status()
            return resp.json()["id"]

    async def ensure_engagement(self, product_id: int, name: str, start: str, end: str) -> int:
        async with self._client() as client:
            resp = await client.get(
                "/api/v2/engagements/",
                params={"product": product_id, "name": name},
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
            if results:
                return results[0]["id"]

            resp = await client.post(
                "/api/v2/engagements/",
                json={
                    "name": name,
                    "product": product_id,
                    "target_start": start,
                    "target_end": end,
                    "engagement_type": "Interactive",
                    "status": "In Progress",
                },
            )
            resp.raise_for_status()
            return resp.json()["id"]

    async def import_scan(
        self,
        engagement_id: int,
        scan_type: str,
        file_content: bytes,
        file_name: str,
    ) -> dict:
        async with self._client() as client:
            resp = await client.post(
                "/api/v2/import-scan/",
                data={
                    "engagement": str(engagement_id),
                    "scan_type": scan_type,
                    "active": "true",
                    "verified": "false",
                },
                files={"file": (file_name, file_content)},
            )
            resp.raise_for_status()
            return resp.json()

    async def get_findings(self, engagement_id: int) -> list[dict]:
        async with self._client() as client:
            resp = await client.get(
                "/api/v2/findings/",
                params={"test__engagement": engagement_id, "limit": 1000},
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
