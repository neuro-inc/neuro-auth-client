import asyncio
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, Optional, cast
from uuid import uuid1

import aiozipkin
import pytest
from aiohttp.test_utils import TestServer as AioHTTPTestServer
from jose import jwk

from auth_server.api import create_app
from auth_server.config import (
    Config as AppConfig,
    DatabaseConfig,
    SecurityConfig,
    UserStorageType,
)
from auth_server.security import JWTCodec
from neuro_auth_client import AuthClient, Permission, User


@pytest.fixture
def random_str() -> Callable[..., str]:
    def _f() -> str:
        return str(uuid1())[:8]

    return _f


@pytest.fixture
def event_loop(loop: asyncio.AbstractEventLoop) -> asyncio.AbstractEventLoop:
    """
    This fixture mitigates the compatibility issues between
    pytest-asyncio and pytest-aiohttp.
    """
    return loop


@pytest.fixture
def hs_jwk() -> Dict[str, str]:
    key = jwk.construct("secret", "HS256").to_dict()
    return {k: v if isinstance(v, str) else v.decode() for k, v in key.items()}


@pytest.fixture
def security_config(hs_jwk: Dict[str, str]) -> SecurityConfig:
    return SecurityConfig(jw_keys=[hs_jwk])


@pytest.fixture
def auth_server_config(security_config: SecurityConfig) -> AppConfig:
    return AppConfig(
        database=cast(DatabaseConfig, None),
        store_type=UserStorageType.IN_MEMORY,
        security=security_config,
    )


@pytest.fixture
async def server(
    aiohttp_server: Any, auth_server_config: AppConfig
) -> AsyncGenerator[AioHTTPTestServer, None]:
    app = await create_app(auth_server_config)
    server = await aiohttp_server(app)
    yield server


@pytest.fixture
def token_factory(security_config: SecurityConfig) -> Callable[[str], str]:
    def _factory(name: str) -> str:
        codec = JWTCodec.from_config(security_config)
        payload = {"identity": name}
        return codec.encode(payload)

    return _factory


@pytest.fixture
def user_token(token_factory: Callable[[str], str]) -> str:
    return token_factory("user")


@pytest.fixture
def admin_token(token_factory: Callable[[str], str]) -> str:
    return token_factory("admin")


@pytest.fixture
async def client(
    server: AioHTTPTestServer, admin_token: str
) -> AsyncGenerator[AuthClient, None]:
    zipkin_address = "http://zipkin"
    endpoint = aiozipkin.create_endpoint("test_service", ipv4="127.0.0.1", port=0)
    tracer = await aiozipkin.create(zipkin_address, endpoint, sample_rate=0)
    trace_configs = []
    trace_config = aiozipkin.make_trace_config(tracer)
    if trace_config is not None:
        trace_configs.append(trace_config)
    async with AuthClient(server.make_url(""), admin_token, trace_configs) as client:
        yield client
    await tracer.close()


@pytest.fixture
async def regular_user_factory(
    client: AuthClient, random_str: Callable[..., str]
) -> Callable[[Optional[str]], Awaitable[User]]:
    async def _factory(
        name: Optional[str] = None, cluster_name: str = "test-cluster"
    ) -> User:
        if not name:
            name = random_str()
        user = User(name=name)
        await client.add_user(user)
        # Grant cluster-specific permissions
        permissions = [
            Permission(uri=f"storage://{cluster_name}/{name}", action="manage"),
            Permission(uri=f"image://{cluster_name}/{name}", action="manage"),
            Permission(uri=f"job://{cluster_name}/{name}", action="manage"),
        ]
        await client.grant_user_permissions(name, permissions)
        return user

    return _factory


@pytest.fixture
async def complex_role_factory(
    client: AuthClient, random_str: Callable[..., str]
) -> Callable[[Optional[str]], Awaitable[str]]:
    async def _factory(name: Optional[str] = None) -> str:
        if not name:
            name = f"company-{random_str()}"
            user = User(name=name)
            await client.add_user(user)
            name = f"{name}/team-{random_str()}"
        user = User(name=name)
        await client.add_user(user)
        return name

    return _factory


@pytest.fixture
def client_factory(
    server: AioHTTPTestServer, token_factory: Callable[..., str]
) -> Callable[[User], AuthClient]:
    def _factory(user: User) -> AuthClient:
        token = token_factory(user.name)
        return AuthClient(server.make_url(""), token)

    return _factory
