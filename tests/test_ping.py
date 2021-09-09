from dataclasses import replace
from decimal import Decimal
from typing import Awaitable, Callable, List

import pytest
from aiohttp.client_exceptions import ClientResponseError

from neuro_auth_client import AuthClient, Cluster, Permission, Quota, User


async def test_ping(client: AuthClient) -> None:
    await client.ping()  # should not raise exception


async def test_secured_ping(client: AuthClient) -> None:
    await client.secured_ping()  # should not raise exception


async def test_get_missing_permissions_empty(client: AuthClient) -> None:
    user_name = "admin"
    permissions: List[Permission] = []
    with pytest.raises(AssertionError, match="No permissions passed"):
        await client.get_missing_permissions(user_name, permissions)


async def test_get_missing_permissions_unknown_scheme(client: AuthClient) -> None:
    user_name = "admin"
    permissions = [Permission(uri="unknown:", action="read")]
    with pytest.raises(
        ClientResponseError, match="422, message='Unknown resource type: unknown'"
    ):
        await client.get_missing_permissions(user_name, permissions)


async def test_get_missing_permissions_ok(client: AuthClient) -> None:
    user_name = "admin"
    permissions = [Permission(uri="user:", action="manage")]
    missing = await client.get_missing_permissions(user_name, permissions)
    assert missing == []


async def test_get_missing_permissions_forbidden(client: AuthClient) -> None:
    # NOTE: this test assumes that the cluster user does not have access
    # to storage: and image: resources
    user_name = "cluster"
    permissions = [Permission(uri="storage:", action="manage")]
    missing = await client.get_missing_permissions(user_name, permissions)
    assert set(missing) == set(permissions)


async def test_get_missing_permissions_forbidden2(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    permissions = [Permission(uri="user:", action="manage")]
    async with client_factory(user) as user_client:
        missing = await user_client.get_missing_permissions(user.name, permissions)
        assert set(missing) == set(permissions)


async def test_get_missing_permissions_forbidden_to_ask(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    # when doing `get_missing_permissions()`, the user must have read perm on
    # `user://{requested_user_name}`
    permissions = [Permission(uri="user:", action="manage")]
    async with client_factory(user) as user_client:
        with pytest.raises(ClientResponseError, match="Forbidden"):
            await user_client.get_missing_permissions("admin", permissions)


async def test_check_user_permissions_empty(client: AuthClient) -> None:
    user_name = "admin"
    permissions: List[Permission] = []
    with pytest.raises(AssertionError, match="No permissions passed"):
        await client.check_user_permissions(user_name, permissions)


async def test_check_user_permissions_unknown_scheme(client: AuthClient) -> None:
    user_name = "admin"
    permissions = [Permission(uri="unknown:", action="read")]
    with pytest.raises(
        ClientResponseError, match="422, message='Unknown resource type: unknown'"
    ):
        await client.check_user_permissions(user_name, permissions)


async def test_check_user_permissions(client: AuthClient) -> None:
    user_name = "admin"
    permissions = [Permission(uri="user:", action="manage")]
    assert await client.check_user_permissions(user_name, permissions)


async def test_check_user_permissions_forbidden(client: AuthClient) -> None:
    # NOTE: this test assumes that the default cluster user does not have access
    # to storage: and image: resources
    user_name = "cluster"
    permissions = [Permission(uri="storage:", action="manage")]
    assert not await client.check_user_permissions(user_name, permissions)


async def test_get_user_not_found(client: AuthClient) -> None:
    user_name = "unknown"
    with pytest.raises(ClientResponseError, match=f'user "{user_name}" was not found'):
        await client.get_user(user_name)


async def test_get_user(client: AuthClient) -> None:
    user = await client.get_user("admin")
    assert user == User(name="admin", clusters=[Cluster(name="default")])


async def test_add_user_update_user(client: AuthClient) -> None:
    original_user = User(
        name="testuser",
        email="sample@example.com",
        clusters=[Cluster(name="testcluster")],
    )
    await client.add_user(original_user)
    user = await client.get_user(original_user.name)
    assert user == original_user

    new_quota = Quota(
        total_running_jobs=10,
    )
    new_cluster = "another-cluster"
    new_email = "other@example.com"
    new_user = User(
        original_user.name,
        clusters=[Cluster(name=new_cluster, quota=new_quota)],
        email=new_email,
    )
    await client.update_user(new_user)
    user = await client.get_user(new_user.name)
    assert user == new_user


async def test_add_user_optional_fields(client: AuthClient) -> None:
    original_user = User(name="testuser")
    await client.add_user(original_user)
    user = await client.get_user(original_user.name)
    assert user == replace(original_user, clusters=[Cluster(name="default")])


async def test_add_user_with_quota(client: AuthClient) -> None:
    original_user = User(
        name="testuser",
        clusters=[
            Cluster(name="testcluster", quota=Quota(credits=Decimal("100"))),
            Cluster(name="testcluster2"),
            Cluster(name="testcluster3", quota=Quota(total_running_jobs=20)),
        ],
    )
    await client.add_user(original_user)
    user = await client.get_user(original_user.name)
    assert user == original_user


async def test_add_complex_role(
    client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
) -> None:
    role = await complex_role_factory()
    user = await client.get_user(role)
    assert user.name == role


async def test_grant_user_permissions_single_ok(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    permissions = [Permission(uri="user:", action="manage")]

    missing = await client.get_missing_permissions(user.name, permissions)
    assert set(missing) == set(permissions)

    await client.grant_user_permissions(user.name, permissions)

    missing = await client.get_missing_permissions(user.name, permissions)
    assert missing == []


async def test_grant_user_permissions_multiple_ok(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    src_user = await regular_user_factory()
    dst_user = await regular_user_factory()
    permissions = [
        Permission(uri=f"job://test-cluster/{src_user.name}", action="manage"),
        Permission(uri=f"storage://test-cluster/{src_user.name}", action="read"),
    ]

    # check that src_user has MANAGE permissions
    manage_permissions = [Permission(uri=p.uri, action="manage") for p in permissions]
    missing = await client.get_missing_permissions(src_user.name, manage_permissions)
    assert missing == []

    # check that dst_user has no permissions
    missing = await client.get_missing_permissions(dst_user.name, permissions)
    assert set(missing) == set(permissions)

    # grant permissions to dst_user
    async with client_factory(src_user) as src_client:
        await src_client.grant_user_permissions(dst_user.name, permissions)

    # check that dst_user has granted permissions
    missing = await client.get_missing_permissions(dst_user.name, permissions)
    assert missing == []


async def test_grant_user_permissions_empty(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    permissions: List[Permission] = []

    with pytest.raises(ClientResponseError, match="list length is less than 1"):
        await client.grant_user_permissions(user.name, permissions)


async def test_grant_complex_role_permissions(
    client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
) -> None:
    role = await complex_role_factory()
    permissions = [Permission(uri="user:", action="manage")]

    missing = await client.get_missing_permissions(role, permissions)
    assert set(missing) == set(permissions)

    await client.grant_user_permissions(role, permissions)

    missing = await client.get_missing_permissions(role, permissions)
    assert missing == []


async def test_grant_user_permissions_internal_auth_exception(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    perms = [Permission(uri="job:job-id", action="read")]

    with pytest.raises(
        ClientResponseError, match="authority is missing, but path part exists"
    ):
        await client.grant_user_permissions(user.name, perms)


async def test_grant_user_permissions_by_regular_user_target_user_not_found(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
    random_str: Callable[..., str],
) -> None:
    user = await regular_user_factory()
    target = f"user-{random_str()}"
    permissions = [Permission(uri=f"job://test-cluster/{user.name}", action="read")]

    with pytest.raises(ClientResponseError, match=f'user "{target}" was not found'):
        await client.get_user(target)

    assert await client.check_user_permissions(user.name, permissions)
    async with client_factory(user) as user_client:
        with pytest.raises(ClientResponseError, match=f'user "{target}" was not found'):
            await user_client.grant_user_permissions(target, permissions)


async def test_grant_user_permissions_by_admin_to_self_allowed(
    client: AuthClient,
) -> None:
    target = "admin"
    permissions = [Permission(uri="job://test-cluster/whatever", action="read")]

    await client.grant_user_permissions(target, permissions)
    assert await client.check_user_permissions(target, permissions)


async def test_grant_user_permissions_normal_user_to_self_forbidden(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    target = user.name
    permissions = [Permission(uri=f"job://test-cluster/{target}", action="read")]

    assert await client.check_user_permissions(user.name, permissions)
    async with client_factory(user) as user_client:
        with pytest.raises(
            ClientResponseError, match="403, message='Adding self user is forbidden'"
        ):
            await user_client.grant_user_permissions(target, permissions)
    assert await client.check_user_permissions(user.name, permissions)


async def test_grant_user_permissions_by_normal_user_no_manage_permissions(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    anotheruser = await regular_user_factory()
    target = anotheruser.name

    # we assume that `client` uses the user `admin` that has permission on
    # `job://test-cluster/admin`
    read_perms = [Permission(uri="job://test-cluster/admin", action="read")]
    manage_perms = [Permission(uri=p.uri, action="manage") for p in read_perms]

    # grant the normal user read-only permissions:
    assert not await client.check_user_permissions(user.name, read_perms)
    await client.grant_user_permissions(user.name, read_perms)
    assert await client.check_user_permissions(user.name, read_perms)
    assert not await client.check_user_permissions(user.name, manage_perms)

    # using user's client, try to revoke manage permissions:
    async with client_factory(user) as user_client:
        with pytest.raises(ClientResponseError, match="Forbidden"):
            await user_client.grant_user_permissions(target, read_perms)

    # check that all permissions remain:
    assert not await client.check_user_permissions(target, read_perms)


async def test_grant_user_permissions_unprocessable_permission(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    anotheruser = await regular_user_factory()
    target = anotheruser.name

    permissions = [Permission(uri="unknown:", action="read")]
    with pytest.raises(
        ClientResponseError, match="422, message='Unknown resource type: unknown'"
    ):
        await client.grant_user_permissions(target, permissions)


async def test_revoke_user_permissions_single_ok(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    uris = [f"user://{user.name}"]
    read_perms = [Permission(uri=u, action="read") for u in uris]

    assert await client.check_user_permissions(user.name, read_perms)
    await client.revoke_user_permissions(user.name, uris)
    assert not await client.check_user_permissions(user.name, read_perms)


async def test_revoke_user_permissions_multiple_ok(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    src_user = await regular_user_factory()
    dst_user = await regular_user_factory()
    permissions = [
        Permission(uri=f"job://test-cluster/{src_user.name}", action="manage"),
        Permission(uri=f"storage://test-cluster/{src_user.name}", action="read"),
    ]

    # first, check that src_user has manage permissions:
    manage_permissions = [Permission(uri=p.uri, action="manage") for p in permissions]
    missing = await client.get_missing_permissions(src_user.name, manage_permissions)
    assert missing == []

    # then, grant the permissions to the dst_user:
    async with client_factory(src_user) as src_client:
        await src_client.grant_user_permissions(dst_user.name, permissions)
    missing = await client.get_missing_permissions(dst_user.name, permissions)
    assert missing == []

    # then, revoke granted permissions:
    uris = [p.uri for p in permissions]
    async with client_factory(src_user) as src_client:
        await src_client.revoke_user_permissions(dst_user.name, uris)
    missing = await client.get_missing_permissions(dst_user.name, permissions)
    assert set(missing) == set(permissions)


async def test_revoke_user_permissions_empty(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    uris: List[str] = []

    with pytest.raises(
        ClientResponseError, match="400, message='\"uri\" request parameter is missing'"
    ):
        await client.revoke_user_permissions(user.name, uris)


async def test_revoke_complex_role_permissions(
    client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
) -> None:
    role = await complex_role_factory()
    uris = [f"user://{role}"]
    read_perms = [Permission(uri=u, action="read") for u in uris]

    assert await client.check_user_permissions(role, read_perms)
    await client.revoke_user_permissions(role, uris)
    assert not await client.check_user_permissions(role, read_perms)


async def test_revoke_user_permissions_internal_auth_exception(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    user = await regular_user_factory()
    uris = ["job:job-id"]

    with pytest.raises(
        ClientResponseError, match="authority is missing, but path part exists"
    ):
        await client.revoke_user_permissions(user.name, uris)


async def test_revoke_user_permissions_by_regular_user_target_user_not_found(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
    random_str: Callable[..., str],
) -> None:
    user = await regular_user_factory()
    target = f"user-{random_str()}"
    uris = [f"job://test-cluster/{user.name}"]
    permissions = [Permission(uri=u, action="read") for u in uris]

    with pytest.raises(ClientResponseError, match=f'user "{target}" was not found'):
        await client.get_user(target)

    assert await client.check_user_permissions(user.name, permissions)
    async with client_factory(user) as user_client:
        with pytest.raises(ClientResponseError, match=f'user "{target}" was not found'):
            await user_client.revoke_user_permissions(target, uris)


async def test_revoke_user_permissions_by_admin_to_self_forbidden(
    client: AuthClient,
) -> None:
    target = "admin"
    uris = [f"job://test-cluster/{target}"]
    permissions = [Permission(uri=u, action="read") for u in uris]

    assert await client.check_user_permissions("admin", permissions)
    with pytest.raises(
        ClientResponseError, match="400, message='Operation has no effect'"
    ):
        await client.revoke_user_permissions(target, uris)
    assert await client.check_user_permissions("admin", permissions)


async def test_revoke_user_permissions_by_normal_user_to_self_forbidden(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    target = user.name
    uris = [f"job://test-cluster/{target}"]
    permissions = [Permission(uri=u, action="read") for u in uris]

    assert await client.check_user_permissions(user.name, permissions)
    async with client_factory(user) as user_client:
        with pytest.raises(
            ClientResponseError, match="403, message='Adding self user is forbidden'"
        ):
            await user_client.grant_user_permissions(target, permissions)
    assert await client.check_user_permissions(user.name, permissions)


async def test_revoke_user_permissions_by_normal_user_no_manage_permissions(
    client: AuthClient,
    regular_user_factory: Callable[..., Awaitable[User]],
    client_factory: Callable[..., AuthClient],
) -> None:
    user = await regular_user_factory()
    anotheruser = await regular_user_factory()
    target = anotheruser.name

    # we assume that `client` uses the user `admin` that can `manage` the
    # `job://test-cluster/admin`
    uris = ["job://test-cluster/admin"]
    read_perms = [Permission(uri=u, action="read") for u in uris]
    manage_perms = [Permission(uri=p.uri, action="manage") for p in read_perms]

    # grant the normal user read-only permissions:
    await client.grant_user_permissions(user.name, read_perms)
    assert await client.check_user_permissions(user.name, read_perms)
    assert not await client.check_user_permissions(user.name, manage_perms)

    # using user's client, try to revoke manage permissions:
    async with client_factory(user) as user_client:
        with pytest.raises(ClientResponseError, match="403, message='Forbidden'"):
            await user_client.revoke_user_permissions(target, uris)

    # check that all permissions remain:
    assert await client.check_user_permissions(user.name, read_perms)
    assert not await client.check_user_permissions(user.name, manage_perms)


async def test_revoke_user_permissions_unprocessable_permission(
    client: AuthClient, regular_user_factory: Callable[..., Awaitable[User]]
) -> None:
    anotheruser = await regular_user_factory()
    target = anotheruser.name

    uris = ["unknown:"]
    with pytest.raises(
        ClientResponseError,
        match=(
            "422, message=\"Malformed URI 'unknown:': "
            'Unknown resource type: unknown."'
        ),
    ):
        await client.revoke_user_permissions(target, uris)
