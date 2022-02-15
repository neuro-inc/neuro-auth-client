import json
import logging
from collections.abc import Sequence
from typing import Union

from aiohttp import ClientError, web
from aiohttp_security import check_authorized
from aiohttp_security.api import AUTZ_KEY

from .client import Permission

logger = logging.getLogger(__name__)


async def check_permissions(
    request: web.Request, permissions: Sequence[Union[Permission, Sequence[Permission]]]
) -> None:
    user_name = await check_authorized(request)
    auth_policy = request.config_dict.get(AUTZ_KEY)
    if not auth_policy:
        raise RuntimeError("Auth policy not configured")

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


def _permission_to_primitive(perm: Permission) -> dict[str, str]:
    return {"uri": perm.uri, "action": perm.action}
