import os

import pytest
import pytest_asyncio

# --- Fixtures for scan parser tests ---


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
    import json

    line1 = json.dumps(
        {
            "template-id": "tech-detect",
            "matched-at": "https://example.com",
            "info": {"name": "Nginx Detection", "severity": "info", "tags": ["tech"]},
            "type": "http",
        }
    )
    line2 = json.dumps(
        {
            "template-id": "cve-2021-44228",
            "matched-at": "https://example.com:8080",
            "info": {
                "name": "Log4j RCE",
                "severity": "critical",
                "description": "Remote code execution via Log4Shell",
                "tags": ["cve", "rce"],
            },
            "type": "http",
            "matcher-name": "log4j",
        }
    )
    return f"{line1}\n{line2}"


@pytest.fixture
def subfinder_jsonl_output():
    return """{"host":"api.example.com","source":"crtsh"}
{"host":"mail.example.com","source":"virustotal"}
{"host":"dev.example.com","source":"securitytrails"}"""


# --- Async app fixtures (require PostgreSQL) ---

# Use a dedicated test DB; skip integration tests if not available.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest_test",
)


def _pg_available() -> bool:
    """Quick sync check whether PostgreSQL test DB is reachable."""
    try:
        import asyncio

        import asyncpg

        async def _check():
            conn = await asyncpg.connect(
                TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
            )
            await conn.close()

        asyncio.run(_check())
        return True
    except Exception:
        return False


requires_pg = pytest.mark.skipif(
    not _pg_available(),
    reason="PostgreSQL test database not available",
)


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    from src.core.models import Base

    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"PostgreSQL test database not available: {exc}")
        return

    try:
        yield engine
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_db(test_engine):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(test_engine):
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from src.api.app import app
    from src.api.deps import get_db

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
