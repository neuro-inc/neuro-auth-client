"""Neuromation auth client."""

from importlib.metadata import version

from .api import UserInfo, check_permissions, get_user, get_user_and_kind
from .client import (
    Action,
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Permission,
    Role,
    User,
)
from .security import (
    JWT_CLUSTER_CLAIM,
    JWT_IDENTITY_CLAIM,
    JWT_KIND_CLAIM,
    IdentityError,
    Kind,
)

__all__ = [
    "Action",
    "AuthClient",
    "ClientAccessSubTreeView",
    "ClientSubTreeViewRoot",
    "JWT_IDENTITY_CLAIM",
    "JWT_KIND_CLAIM",
    "JWT_CLUSTER_CLAIM",
    "IdentityError",
    "Kind",
    "Permission",
    "Role",
    "User",
    "UserInfo",
    "check_permissions",
    "get_user",
    "get_user_and_kind",
]
__version__ = version(__package__)
