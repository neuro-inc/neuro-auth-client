import pytest
from yarl import URL

from neuro_auth_client.client import (
    Action,
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Permission,
    check_action_allowed,
)


class TestAction:
    def test_str(self) -> None:
        assert str(Action.READ) == "read"


class TestPermission:
    def test_actions(self) -> None:
        for action in "deny", "list", "read", "write", "manage":
            permission = Permission(
                uri="storage://test-cluster/user/folder", action=action
            )
            assert permission.uri == "storage://test-cluster/user/folder"
            assert permission.action == action

    def test_can_list(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_list()
        assert Permission(uri, "list").can_list()
        assert Permission(uri, "read").can_list()
        assert Permission(uri, "write").can_list()
        assert Permission(uri, "manage").can_list()

    def test_can_read(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_read()
        assert not Permission(uri, "list").can_read()
        assert Permission(uri, "read").can_read()
        assert Permission(uri, "write").can_read()
        assert Permission(uri, "manage").can_read()

    def test_can_write(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_write()
        assert not Permission(uri, "list").can_write()
        assert not Permission(uri, "read").can_write()
        assert Permission(uri, "write").can_write()
        assert Permission(uri, "manage").can_write()


class TestTree:
    def test_tree_contains_permissions(self) -> None:
        tree = ClientSubTreeViewRoot._from_json(
            "storage",
            {
                "path": "/cluster",
                "action": "list",
                "children": {
                    "username1": {
                        "action": "write",
                        "children": {},
                    },
                    "username2": {
                        "action": "read",
                        "children": {},
                    },
                    "username3": {
                        "action": "list",
                        "children": {
                            "subpath": {
                                "action": "write",
                                "children": {},
                            }
                        },
                    },
                },
            },
        )
        for result, perm in [
            (True, Permission("storage://cluster/username1", "write")),
            (True, Permission("storage://cluster/username1", "read")),
            (True, Permission("storage://cluster/username2", "read")),
            (True, Permission("storage://cluster/username3/subpath", "write")),
            (
                True,
                Permission("storage://cluster/username1/very/deep/subpath", "write"),
            ),
            (True, Permission("storage://cluster/username2/very/deep/subpath", "read")),
            (False, Permission("storage://cluster/username4", "read")),
            (False, Permission("storage://cluster/username2", "write")),
            (False, Permission("storage://cluster/username3/another", "read")),
            (False, Permission("storage://cluster2", "list")),
            (False, Permission("blob://cluster/username1", "write")),
        ]:
            assert result == tree.allows(perm), perm

    def test_tree_contains_permissions_2(self) -> None:
        tree = ClientSubTreeViewRoot._from_json(
            "storage",
            {
                "path": "/cluster/",
                "action": "list",
                "children": {
                    "username1": {
                        "action": "write",
                        "children": {},
                    },
                    "username2": {
                        "action": "read",
                        "children": {},
                    },
                    "username3": {
                        "action": "list",
                        "children": {
                            "subpath": {
                                "action": "write",
                                "children": {},
                            }
                        },
                    },
                },
            },
        )
        for result, perm in [
            (True, Permission("storage://cluster/username1", "write")),
            (True, Permission("storage://cluster/username1", "read")),
            (True, Permission("storage://cluster/username2", "read")),
            (True, Permission("storage://cluster/username3/subpath", "write")),
            (
                True,
                Permission("storage://cluster/username1/very/deep/subpath", "write"),
            ),
            (True, Permission("storage://cluster/username2/very/deep/subpath", "read")),
            (False, Permission("storage://cluster/username4", "read")),
            (False, Permission("storage://cluster/username2", "write")),
            (False, Permission("storage://cluster/username3/another", "read")),
            (False, Permission("storage://cluster2", "list")),
            (False, Permission("blob://cluster/username1", "write")),
        ]:
            assert result == tree.allows(perm), perm

    def test_tree_contains_permissions_empty_path(self) -> None:
        tree = ClientSubTreeViewRoot._from_json(
            "storage",
            {
                "path": "/",
                "action": "list",
                "children": {
                    "test1": {
                        "action": "write",
                        "children": {},
                    },
                    "test2": {
                        "action": "read",
                        "children": {},
                    },
                    "test3": {
                        "action": "list",
                        "children": {
                            "subpath": {
                                "action": "write",
                                "children": {},
                            }
                        },
                    },
                },
            },
        )
        for result, perm in [
            (True, Permission("storage://test1", "write")),
            (True, Permission("storage://test2", "read")),
            (True, Permission("storage://test2", "read")),
            (True, Permission("storage://test3/subpath", "write")),
            (
                True,
                Permission("storage://test1/very/deep/subpath", "write"),
            ),
            (True, Permission("storage://test2/very/deep/subpath", "read")),
            (False, Permission("storage://test4", "read")),
            (False, Permission("storage://test2", "write")),
            (False, Permission("storage://test3/another", "read")),
            (False, Permission("blob://test1", "write")),
        ]:
            assert result == tree.allows(perm), perm

    def test_can_list(self) -> None:
        assert not ClientAccessSubTreeView("deny", {}).can_list()
        assert ClientAccessSubTreeView("list", {}).can_list()
        assert ClientAccessSubTreeView("read", {}).can_list()
        assert ClientAccessSubTreeView("write", {}).can_list()
        assert ClientAccessSubTreeView("manage", {}).can_list()

    def test_can_read(self) -> None:
        assert not ClientAccessSubTreeView("deny", {}).can_read()
        assert not ClientAccessSubTreeView("list", {}).can_read()
        assert ClientAccessSubTreeView("read", {}).can_read()
        assert ClientAccessSubTreeView("write", {}).can_read()
        assert ClientAccessSubTreeView("manage", {}).can_read()

    def test_can_write(self) -> None:
        assert not ClientAccessSubTreeView("deny", {}).can_write()
        assert not ClientAccessSubTreeView("list", {}).can_write()
        assert not ClientAccessSubTreeView("read", {}).can_write()
        assert ClientAccessSubTreeView("write", {}).can_write()
        assert ClientAccessSubTreeView("manage", {}).can_write()


class TestUtils:
    def test_check_action_allowed(self) -> None:
        assert not check_action_allowed("deny", "list")
        assert check_action_allowed("list", "list")
        assert check_action_allowed("read", "list")
        assert check_action_allowed("write", "list")
        assert check_action_allowed("manage", "list")

        assert not check_action_allowed("deny", "read")
        assert not check_action_allowed("list", "read")
        assert check_action_allowed("read", "read")
        assert check_action_allowed("write", "read")
        assert check_action_allowed("manage", "read")

        assert not check_action_allowed("deny", "write")
        assert not check_action_allowed("list", "write")
        assert not check_action_allowed("read", "write")
        assert check_action_allowed("write", "write")
        assert check_action_allowed("manage", "write")

        assert not check_action_allowed("deny", "manage")
        assert not check_action_allowed("list", "manage")
        assert not check_action_allowed("read", "manage")
        assert not check_action_allowed("write", "manage")
        assert check_action_allowed("manage", "manage")

    def test_check_action_allowed_errors(self) -> None:
        with pytest.raises(ValueError, match="create"):
            assert check_action_allowed("read", "create")
        with pytest.raises(ValueError, match="forbid"):
            assert check_action_allowed("forbid", "read")


class TestClient:
    async def test_https_url(self) -> None:
        async with AuthClient(URL("https://example.com"), "<token>") as client:
            assert client._url == URL("https://example.com")

    async def test_null_url(self) -> None:
        async with AuthClient(None, "<token>") as client:
            assert client._url is None

    async def test_empty_url(self) -> None:
        with pytest.raises(ValueError):
            AuthClient(URL(), "<token>")
