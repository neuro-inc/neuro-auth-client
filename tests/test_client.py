import pytest

from neuro_auth_client.client import (
    ClientAccessSubTreeView,
    Permission,
    check_action_allowed,
)


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
