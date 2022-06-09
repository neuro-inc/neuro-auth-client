"""Neuromation auth client."""
from importlib.metadata import version

from .api import check_permissions
from .client import (
    Action,
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Permission,
    Role,
    User,
)

__all__ = [
    "Action",
    "AuthClient",
    "ClientAccessSubTreeView",
    "ClientSubTreeViewRoot",
    "Permission",
    "Role",
    "User",
    "check_permissions",
]
__version__ = version(__package__)
