from dataclasses import replace
from typing import Awaitable, Callable

import pytest
from aiohttp.client import ClientResponseError

from neuro_auth_client import AuthClient, Permission, User, Cluster


class TestEnsureTreeOperations:
    async def prepare_user(
        self, client: AuthClient, user_name: str, cluster_name: str = "test-cluster"
    ) -> None:
        u1 = User(name=user_name)
        await client.add_user(u1)
        # Grant cluster-specific permissions
        permissions = [
            Permission(uri=f"storage://{cluster_name}/{user_name}", action="manage"),
            Permission(uri=f"image://{cluster_name}/{user_name}", action="manage"),
            Permission(uri=f"job://{cluster_name}/{user_name}", action="manage"),
        ]
        await client.grant_user_permissions(user_name, permissions)

    async def test_user_checks_home(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(
            uname, f"storage://test-cluster/{uname}"
        )
        assert tree
        assert tree.path == f"/test-cluster/{uname}"
        assert tree.sub_tree
        assert tree.sub_tree.action == "manage"

    async def test_user_checks_owned_subdir(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(
            uname, f"storage://test-cluster/{uname}/my_dir"
        )
        assert tree
        assert tree.path == f"/test-cluster/{uname}/my_dir"
        assert tree.sub_tree
        assert tree.sub_tree.action == "manage"

    async def test_user_checks_non_shared_home(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(
            uname, f"storage://test-cluster/another{uname}"
        )
        assert tree
        assert tree.path == f"/test-cluster/another{uname}"
        assert tree.sub_tree
        assert tree.sub_tree.action == "deny"

    async def test_user_checks_non_shared_subdir(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(
            uname, f"storage://test-cluster/another{uname}/my_dir"
        )
        assert tree
        assert tree.path == f"/test-cluster/another{uname}/my_dir"
        assert tree.sub_tree
        assert tree.sub_tree.action == "deny"

    async def test_user_checks_storage_root(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(uname, "storage:")
        assert tree
        assert tree.path == "/"
        assert tree.sub_tree
        assert tree.sub_tree.action == "list"
        assert tree.sub_tree.children["test-cluster"].action == "list"
        assert tree.sub_tree.children["test-cluster"].children[uname].action == "manage"

    async def test_user_checks_storage_root_2(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(uname, "storage://")
        assert tree
        assert tree.path == "/"
        assert tree.sub_tree
        assert tree.sub_tree.action == "list"
        assert tree.sub_tree.children["test-cluster"].action == "list"
        assert tree.sub_tree.children["test-cluster"].children[uname].action == "manage"

    async def test_user_checks_storage_root_depth_2(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(uname, "storage:", depth=2)
        assert tree
        assert tree.path == "/"
        assert tree.sub_tree
        assert tree.sub_tree.action == "list"
        assert tree.sub_tree.children["test-cluster"].action == "list"
        assert tree.sub_tree.children["test-cluster"].children[uname].action == "manage"

    async def test_user_checks_storage_root_depth_1(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(uname, "storage:", depth=1)
        assert tree
        assert tree.path == "/"
        assert tree.sub_tree
        assert tree.sub_tree.action == "list"
        assert tree.sub_tree.children == {}

    async def test_user_checks_storage_root_depth_0(self, client: AuthClient) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        tree = await client.get_permissions_tree(uname, "storage:", depth=0)
        assert tree
        assert tree.path == "/"
        assert tree.sub_tree
        assert tree.sub_tree.action == "list"
        assert tree.sub_tree.children == {}

    async def test_user_checks_storage_root_1_invalid_url(
        self, client: AuthClient
    ) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        with pytest.raises(
            ClientResponseError,
            match=(
                "400, message=\"Malformed URI 'storage:/': "
                'authority is missing, but path part exists"'
            ),
        ):
            await client.get_permissions_tree(uname, "storage:/")

    async def test_user_checks_storage_root_2_invalid_url(
        self, client: AuthClient
    ) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        with pytest.raises(
            ClientResponseError,
            match=(
                "400, message=\"Malformed URI 'storage:///': "
                'authority is missing, but path part exists"'
            ),
        ):
            await client.get_permissions_tree(uname, "storage:///")

    async def test_complex_role(
        self, client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
    ) -> None:
        role = await complex_role_factory()
        tree = await client.get_permissions_tree(role, f"user://{role}")
        assert tree
        assert tree.path == f"/{role}"
        assert tree.sub_tree
        assert tree.sub_tree.action == "read"

    async def test_get_token(
        self, client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
    ) -> None:
        uname = "user1"
        await self.prepare_user(client, uname)
        token = await client.get_user_token(uname)
        user_info = await client.get_user(uname, token)
        assert user_info.name == uname

    async def test_get_token_with_uri(
        self, client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
    ) -> None:
        uname = "user1"
        token_uri = "token://test-token"
        await self.prepare_user(client, uname)
        token = await client.get_user_token(uname, token_uri)
        await client.grant_user_permissions(uname, [Permission(token_uri, "read")])
        user_info = await client.get_user(uname, token)
        assert user_info.name == uname

    async def test_linked_users(
        self, client: AuthClient, complex_role_factory: Callable[..., Awaitable[str]]
    ) -> None:
        initial_clusters = [Cluster(name="initial")]

        user1 = User(name="testuser1", clusters=initial_clusters)
        user2 = User(
            name="testuser1/subuser",
            clusters=initial_clusters,
        )

        for user in [user1, user2]:
            await client.add_user(user)

        assert (await client.get_user(user2.name)).clusters == initial_clusters
        clusters = [Cluster(name="test")]
        user1 = replace(user1, clusters=clusters)
        await client.update_user(user1)
        assert (await client.get_user(user2.name)).clusters == clusters
