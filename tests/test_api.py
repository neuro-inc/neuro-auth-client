from typing import Any, Awaitable, Callable, List

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient as _TestClient
from aiohttp.web_middlewares import middleware

from neuro_auth_client import AuthClient, Permission, User
from neuro_auth_client.api import check_permissions
from neuro_auth_client.security import setup_security


_TestAppFactory = Callable[..., Awaitable[web.Application]]
_TestClientFactory = Callable[..., Awaitable[_TestClient]]


@pytest.fixture
async def app_factory() -> _TestAppFactory:
    async def _f(
        auth_client: AuthClient, permissions: List[Permission]
    ) -> web.Application:
        async def handler(request: web.Request) -> web.Response:
            await check_permissions(request, permissions)
            return web.Response()

        @middleware
        async def handle_exceptions(
            request: web.Request,
            handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
        ) -> web.StreamResponse:
            try:
                return await handler(request)
            except web.HTTPException:
                raise
            except Exception as e:
                payload = {"error": str(e)}
                return web.json_response(payload, status=500)

        app = web.Application(middlewares=[handle_exceptions])
        app.router.add_get("/", handler)
        await setup_security(app, auth_client)
        return app

    return _f


@pytest.fixture
async def app_client_factory(aiohttp_client: Any) -> _TestClientFactory:
    async def _f(app: web.Application, token: str) -> _TestClient:
        headers = {"Authorization": f"Bearer {token}"}
        return await aiohttp_client(app, headers=headers)

    return _f


async def test_check_permissions_empty(
    client: AuthClient,
    app_factory: _TestAppFactory,
    app_client_factory: _TestClientFactory,
    admin_token: str,
) -> None:
    permissions: List[Permission] = []

    app = await app_factory(client, permissions)
    app_client = await app_client_factory(app, admin_token)

    async with app_client.get("/") as resp:
        assert resp.status == 500, await resp.text()
        payload = await resp.json()
        assert payload == {"error": "No permissions passed"}


async def test_check_permissions_error_caught(
    client: AuthClient,
    app_factory: _TestAppFactory,
    app_client_factory: _TestClientFactory,
    admin_token: str,
) -> None:
    permissions = [Permission(uri="unknown:", action="read")]

    app = await app_factory(client, permissions)
    app_client = await app_client_factory(app, admin_token)

    async with app_client.get("/") as resp:
        assert resp.status == 500, await resp.text()
        payload = await resp.json()
        assert "error" in payload
        assert payload["error"].startswith("422, ")


async def test_check_permissions_ok(
    client: AuthClient,
    app_factory: _TestAppFactory,
    app_client_factory: _TestClientFactory,
    admin_token: str,
) -> None:
    permissions = [Permission(uri="user:", action="manage")]

    app = await app_factory(client, permissions)
    app_client = await app_client_factory(app, admin_token)

    async with app_client.get("/") as resp:
        assert resp.status == 200, await resp.text()


async def test_check_permissions_forbidden(
    client: AuthClient,
    app_factory: _TestAppFactory,
    app_client_factory: _TestClientFactory,
    user_token: str,
    admin_token: str,
) -> None:
    await client.add_user(User("user"), admin_token)

    permissions = [Permission(uri="storage:", action="manage")]

    app = await app_factory(client, permissions)
    app_client = await app_client_factory(app, user_token)

    async with app_client.get("/") as resp:
        assert resp.status == 403, await resp.text()
        payload = await resp.json()
        assert payload == {"missing": [{"action": "manage", "uri": "storage:"}]}
