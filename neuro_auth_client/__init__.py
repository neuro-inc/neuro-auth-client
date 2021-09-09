"""Neuromation auth client."""
from pkg_resources import get_distribution

from .api import check_permissions
from .client import (
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Cluster,
    Permission,
    Quota,
    User,
)


__all__ = [
    "AuthClient",
    "ClientAccessSubTreeView",
    "ClientSubTreeViewRoot",
    "Cluster",
    "Permission",
    "Quota",
    "User",
    "check_permissions",
]
__version__ = get_distribution(__name__).version
