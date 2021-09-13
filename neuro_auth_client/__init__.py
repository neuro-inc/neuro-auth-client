"""Neuromation auth client."""
from pkg_resources import get_distribution

from .api import check_permissions
from .client import (
    Action,
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Cluster,
    Permission,
    Quota,
    Role,
    User,
)


__all__ = [
    "Action",
    "AuthClient",
    "ClientAccessSubTreeView",
    "ClientSubTreeViewRoot",
    "Cluster",
    "Permission",
    "Quota",
    "Role",
    "User",
    "check_permissions",
]
__version__ = get_distribution(__name__).version
