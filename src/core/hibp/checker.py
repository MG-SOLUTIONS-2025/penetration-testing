"""HIBP (Have I Been Pwned) credential leak detection using k-anonymity."""

import hashlib

import httpx

from src.core.config import settings

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORD_API = "https://api.pwnedpasswords.com/range"


async def check_email_breaches(email: str) -> list[dict]:
    """Check if an email appears in known data breaches via HIBP API."""
    if not settings.hibp_api_key:
        raise ValueError("HIBP API key not configured")

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{HIBP_API_BASE}/breachedaccount/{email}",
            headers={
                "hibp-api-key": settings.hibp_api_key,
                "user-agent": "PenTest-Platform",
            },
            params={"truncateResponse": "false"},
            timeout=15.0,
        )

        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            raise RuntimeError("HIBP rate limit exceeded")
        resp.raise_for_status()

        breaches = resp.json()
        return [
            {
                "breach_name": b["Name"],
                "breach_date": b.get("BreachDate"),
                "data_classes": b.get("DataClasses", []),
            }
            for b in breaches
        ]


async def check_password_pwned(password: str) -> int:
    """Check if a password appears in HIBP Passwords using k-anonymity.

    Returns the number of times the password has been seen (0 if not found).
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{HIBP_PASSWORD_API}/{prefix}", timeout=10.0)
        resp.raise_for_status()

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0
