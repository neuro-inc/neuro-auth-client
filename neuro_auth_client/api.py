import dataclasses
import json
import logging
from collections.abc import Sequence
from typing import Union

from aiohttp import ClientError, web
from aiohttp_security import check_authorized
from aiohttp_security.api import AUTZ_KEY, IDENTITY_KEY

from .client import Permission
from .security import AuthPolicy, Kind

logger = logging.getLogger(__name__)


async def check_permissions(
    request: web.Request, permissions: Sequence[Union[Permission, Sequence[Permission]]]
) -> None:
    user_name = await check_authorized(request)
    auth_policy = request.config_dict.get(AUTZ_KEY)
    if not auth_policy:
        raise RuntimeError("Auth policy not configured")
    assert isinstance(auth_policy, AuthPolicy)

    try:
        missing = await auth_policy.get_missing_permissions(user_name, permissions)
    except ClientError as e:
        # re-wrap in order not to expose the client
        raise RuntimeError(e) from e

    if missing:
        payload = {"missing": [_permission_to_primitive(p) for p in missing]}
        raise web.HTTPForbidden(
            text=json.dumps(payload), content_type="application/json"
        )


@dataclasses.dataclass(frozen=True)
class UserInfo:
    userid: str
    kind: Kind
    cluster: str | None  # non if kind != Kind.CLUSTER


async def get_user_and_kind(request: web.Request) -> tuple[str, Kind]:
    # Deprecated, user get_user() instead
    user = await get_user(request)
    return user.userid, user.kind


async def get_user(request: web.Request) -> UserInfo:
    identity_policy = request.config_dict.get(IDENTITY_KEY)
    if not identity_policy:
        raise RuntimeError("Identity policy not configured")
    auth_policy = request.config_dict.get(AUTZ_KEY)
    if not auth_policy:
        raise RuntimeError("Auth policy not configured")
    assert isinstance(auth_policy, AuthPolicy)
    identity = await identity_policy.identify(request)
    if identity is None:
        raise web.HTTPUnauthorized()
    userid = await auth_policy.authorized_userid(identity)
    if userid is None:
        raise web.HTTPUnauthorized()
    kind = auth_policy.get_kind(identity)
    cluster = auth_policy.get_cluster(identity) if kind is Kind.CLUSTER else None
    return UserInfo(userid, kind, cluster)


def _permission_to_primitive(perm: Permission) -> dict[str, str]:
    return {"uri": perm.uri, "action": perm.action}
