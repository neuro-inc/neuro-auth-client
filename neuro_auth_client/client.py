import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from enum import Enum, unique
from typing import Any, Optional, Union

import aiohttp
from aiohttp.hdrs import AUTHORIZATION
from aiohttp.web import HTTPCreated, HTTPNoContent
from multidict import CIMultiDict, MultiDict
from yarl import URL

from .bearer_auth import BearerAuth


@dataclass(frozen=True)
class Quota:
    credits: Optional[Decimal] = None
    total_running_jobs: Optional[int] = None


@dataclass(frozen=True)
class Cluster:
    name: str
    quota: Quota = field(default_factory=Quota)


@dataclass(frozen=True)
class User:
    name: str
    email: Optional[str] = None
    # TODO (ajuszkowsi, March 2019) support "is_disabled" field
    clusters: list[Cluster] = field(default_factory=list)


@unique
class Action(str, Enum):
    READ = "read"
    WRITE = "write"
    MANAGE = "manage"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.__str__().__repr__()


@dataclass(frozen=True)
class Permission:
    uri: str
    action: str

    def check_action_allowed(self, requested: str) -> bool:
        return check_action_allowed(self.action, requested)

    def can_list(self) -> bool:
        return check_action_allowed(self.action, "list")

    def can_read(self) -> bool:
        return check_action_allowed(self.action, "read")

    def can_write(self) -> bool:
        return check_action_allowed(self.action, "write")


@dataclass(frozen=True)
class Role:
    name: str
    permissions: Sequence[Permission]

    def to_role_permission(self, *, action: Action = Action.READ) -> Permission:
        return Permission(f"role://{self.name}", action)


@dataclass
class ClientAccessSubTreeView:
    action: str
    children: dict[str, "ClientAccessSubTreeView"]

    @classmethod
    def _from_json(cls, json_as_dict: dict[str, Any]) -> "ClientAccessSubTreeView":
        action = json_as_dict["action"]
        children = {
            name: ClientAccessSubTreeView._from_json(tree)
            for name, tree in json_as_dict["children"].items()
        }
        return ClientAccessSubTreeView(action, children)

    def check_action_allowed(self, requested: str) -> bool:
        return check_action_allowed(self.action, requested)

    def can_list(self) -> bool:
        return check_action_allowed(self.action, "list")

    def can_read(self) -> bool:
        return check_action_allowed(self.action, "read")

    def can_write(self) -> bool:
        return check_action_allowed(self.action, "write")


@dataclass
class ClientSubTreeViewRoot:
    scheme: str
    path: str
    sub_tree: ClientAccessSubTreeView

    def allows(self, perm: Permission) -> bool:
        perm_uri = URL(perm.uri)
        if perm_uri.scheme != self.scheme:
            return False
        perm_uri_no_scheme = (perm_uri.host or "") + perm_uri.path
        path_no_slash = self.path.lstrip("/").rstrip("/")
        if not perm_uri_no_scheme.startswith(path_no_slash):
            return False
        perm_uri_no_common_path = perm_uri_no_scheme[len(path_no_slash) :]
        if path_no_slash:
            if not perm_uri_no_common_path.startswith("/"):
                return False
            # [1:] to skip first "/":
            perm_uri_no_common_path = perm_uri_no_common_path[1:]
        parts = perm_uri_no_common_path.split("/")
        node = self.sub_tree
        for part in parts:
            if node.check_action_allowed(perm.action):
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return node.check_action_allowed(perm.action)

    @classmethod
    def _from_json(
        cls, scheme: str, json_as_dict: dict[str, Any]
    ) -> "ClientSubTreeViewRoot":
        subtree_path = json_as_dict["path"]
        sub_tree = ClientAccessSubTreeView._from_json(json_as_dict)
        return ClientSubTreeViewRoot(scheme, subtree_path, sub_tree)


class AuthClient:
    def __init__(
        self,
        url: Optional[URL],
        token: str,
        trace_configs: Optional[list[aiohttp.TraceConfig]] = None,
    ) -> None:
        if url is not None and not url:
            raise ValueError(
                "url argument should be http URL or None for secure-less configurations"
            )
        self._token = token
        headers = self._generate_headers(token)
        self._client = aiohttp.ClientSession(
            headers=headers, trace_configs=trace_configs
        )
        self._url = url

    async def __aenter__(self) -> "AuthClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _generate_headers(self, token: Optional[str] = None) -> "CIMultiDict[str]":
        headers: "CIMultiDict[str]" = CIMultiDict()
        if token:
            headers[AUTHORIZATION] = BearerAuth(token).encode()
        return headers

    def _make_url(self, path: str) -> URL:
        assert self._url
        if path.startswith("/"):
            path = path[1:]
        return self._url / path

    def _serialize_quota(self, quota: Quota) -> dict[str, Any]:
        result: dict[str, Any] = {}
        q_running_jobs = quota.total_running_jobs
        if q_running_jobs is not None:
            result["total_running_jobs"] = q_running_jobs
        credits = quota.credits
        if credits is not None:
            result["credits"] = str(credits)
        return result

    async def close(self) -> None:
        await self._client.close()

    @asynccontextmanager
    async def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional["CIMultiDict[str]"] = None,
        json: Any = None,
        params: Optional[Mapping[str, str]] = None,
        raise_for_status: bool = True,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        url = self._make_url(path)
        resp = await self._client.request(
            method, url, headers=headers, params=params, json=json
        )
        if raise_for_status:
            await _raise_for_status(resp)

        try:
            yield resp
        finally:
            resp.release()

    @property
    def is_anonymous_access_allowed(self) -> bool:
        return self._url is None

    async def ping(self) -> None:
        if self._url is None:
            return
        async with self._request("GET", "/api/v1/ping") as resp:
            txt = await resp.text()
            assert txt == "Pong"

    async def secured_ping(self, token: Optional[str] = None) -> None:
        if self._url is None:
            return
        path = "/api/v1/secured-ping"
        headers = self._generate_headers(token)
        async with self._request("GET", path, headers=headers) as resp:
            txt = await resp.text()
            assert txt == "Secured Pong"

    def _serialize_user(self, user: User) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": user.name}
        if user.clusters:
            payload["clusters"] = [self._serialize_cluster(c) for c in user.clusters]
        if user.email:
            payload["email"] = user.email
        return payload

    def _serialize_cluster(self, cluster: Cluster) -> dict[str, Any]:
        return {"name": cluster.name, "quota": self._serialize_quota(cluster.quota)}

    async def add_user(self, user: User, token: Optional[str] = None) -> None:
        path = "/api/v1/users"
        headers = self._generate_headers(token)
        payload = self._serialize_user(user)
        async with self._request("POST", path, headers=headers, json=payload):
            pass  # use context manager to release response earlier

    def _get_user_path(self, name: str) -> str:
        name = name.replace("/", ":")
        return f"/api/v1/users/{name}"

    async def update_user(self, user: User, token: Optional[str] = None) -> None:
        if self._url is None:
            return
        path = self._get_user_path(user.name)
        headers = self._generate_headers(token)
        payload = self._serialize_user(user)
        async with self._request("PUT", path, headers=headers, json=payload):
            pass  # use context manager to release response earlier

    async def get_user(self, name: str, token: Optional[str] = None) -> User:
        if self._url is None:
            return User(
                name="user",
                email="email@example.com",
                clusters=[
                    Cluster(
                        name="default",
                        quota=Quota(
                            credits=None,
                            total_running_jobs=None,
                        ),
                    )
                ],
            )
        path = self._get_user_path(name)
        headers = self._generate_headers(token)
        async with self._request("GET", path, headers=headers) as resp:
            payload = await resp.json()
            return User(
                name=payload["name"],
                email=payload.get("email"),
                clusters=[
                    self._deserialize_cluster(c) for c in payload.get("clusters", [])
                ],
            )

    def _deserialize_cluster(self, payload: dict[str, Any]) -> Cluster:
        quota_payload = payload.get("quota", {})
        credits = quota_payload.get("credits")
        if credits is not None:
            credits = Decimal(credits)
        quota_jobs = quota_payload.get("total_running_jobs")
        quota = Quota(
            credits=credits,
            total_running_jobs=quota_jobs,
        )
        return Cluster(name=payload["name"], quota=quota)

    async def check_user_permissions(
        self,
        name: str,
        permissions: Sequence[Union[Permission, Sequence[Permission]]],
        token: Optional[str] = None,
    ) -> bool:
        if self._url is None:
            return True
        missing = await self.get_missing_permissions(name, permissions, token)
        return not missing

    async def get_missing_permissions(
        self,
        name: str,
        permissions: Sequence[Union[Permission, Sequence[Permission]]],
        token: Optional[str] = None,
    ) -> Sequence[Permission]:
        assert permissions, "No permissions passed"
        if self._url is None:
            return []
        path = self._get_user_path(name) + "/permissions/check"
        headers = self._generate_headers(token)
        payload: list[dict[str, Any]] = []
        has_alternatives = False
        for p in permissions:
            if isinstance(p, Permission):
                payload.append(asdict(p))
            else:
                has_alternatives = True
                for p2 in p:
                    payload.append(asdict(p2))
        async with self._request(
            "POST", path, headers=headers, json=payload, raise_for_status=False
        ) as resp:
            if resp.status not in (200, 403):
                await _raise_for_status(resp)
            data = await resp.json()
            if "missing" not in data:
                assert resp.status == 403, f"unexpected response {resp.status}: {data}"
                await _raise_for_status(resp)

            missing = [self._permission_from_primitive(p) for p in data["missing"]]
        if not missing or not has_alternatives:
            return missing
        required: set[Permission] = set()
        for p in permissions:
            if not isinstance(p, Permission):
                if all(p2 in missing for p2 in p):
                    required.update(p)
            else:
                required.add(p)
        return [p for p in missing if p in required]

    def _permission_from_primitive(self, perm: dict[str, str]) -> Permission:
        return Permission(uri=perm["uri"], action=perm["action"])

    async def get_permissions_tree(
        self, name: str, resource: str, depth: Optional[int] = None
    ) -> ClientSubTreeViewRoot:
        if self._url is None:
            return ClientSubTreeViewRoot(
                scheme=URL(resource).scheme,
                path="/default/user",
                sub_tree=ClientAccessSubTreeView(action="manage", children={}),
            )
        url = self._get_user_path(name) + "/permissions/tree"
        req_params: dict[str, Any] = {"uri": resource}
        if depth is not None:
            req_params["depth"] = depth
        async with self._request("GET", url, params=req_params) as resp:
            payload = await resp.json()
            tree = ClientSubTreeViewRoot._from_json(URL(resource).scheme, payload)
            return tree

    async def grant_user_permissions(
        self, name: str, permissions: Sequence[Permission], token: Optional[str] = None
    ) -> None:
        if self._url is None:
            return
        path = self._get_user_path(name) + "/permissions"
        headers = self._generate_headers(token)
        payload: list[dict[str, str]] = [asdict(p) for p in permissions]
        async with self._request("POST", path, headers=headers, json=payload) as resp:
            status = resp.status
            assert status == HTTPCreated.status_code, f"unexpected response: {status}"

    async def revoke_user_permissions(
        self, name: str, resources_uris: Sequence[str], token: Optional[str] = None
    ) -> None:
        if self._url is None:
            return
        path = self._get_user_path(name) + "/permissions"
        headers = self._generate_headers(token)
        params = MultiDict(("uri", uri) for uri in resources_uris)
        async with self._request(
            "DELETE", path, headers=headers, params=params
        ) as resp:
            status = resp.status
            assert status == HTTPNoContent.status_code, f"unexpected response: {status}"

    async def get_user_token(
        self,
        name: str,
        new_token_uri: Optional[str] = None,
        token: Optional[str] = None,
    ) -> str:
        if self._url is None:
            return ""
        path = self._get_user_path(name) + "/token"
        headers = self._generate_headers(token)
        if new_token_uri:
            data = dict(uri=new_token_uri)
        else:
            data = dict()
        async with self._request("POST", path, headers=headers, json=data) as resp:
            payload = await resp.json()
            return payload["access_token"]

    async def update_role(self, role: User) -> None:
        if self._url is None:
            return
        try:
            await self.update_user(role)
        except aiohttp.ClientResponseError as exc:
            if exc.status != 404:
                raise

            await self.add_user(role)

    async def grant_role_permissions(
        self,
        role_name: str,
        permissions: Sequence[Permission],
        ignore_existing_role: bool = True,
    ) -> None:
        assert permissions
        if self._url is None:
            return
        try:
            await self.grant_user_permissions(role_name, permissions)
        except aiohttp.ClientResponseError as exc:
            if exc.status != 404:
                raise

            await self.add_user(User(name=role_name))
            await self.grant_user_permissions(role_name, permissions)

    async def set_role_permissions(
        self,
        role_name: str,
        permissions: Sequence[Permission],
        ignore_existing_role: bool = True,
    ) -> None:
        assert permissions
        if self._url is None:
            return
        try:
            await self._set_user_permissions(role_name, permissions)
        except aiohttp.ClientResponseError as exc:
            if exc.status != 404:
                raise

            await self.add_user(User(name=role_name))
            await self._set_user_permissions(role_name, permissions)

    async def _set_user_permissions(
        self, name: str, permissions: Sequence[Permission]
    ) -> None:
        path = self._get_user_path(name) + "/permissions"
        payload: list[dict[str, str]] = [asdict(p) for p in permissions]
        async with self._request("PUT", path, json=payload) as resp:
            status = resp.status
            assert (
                status == aiohttp.web.HTTPNoContent.status_code
            ), f"unexpected response: {status}"

    async def revoke_role_permissions(
        self, role_name: str, permissions: Sequence[Permission]
    ) -> None:
        assert permissions
        if self._url is None:
            return
        for perm in permissions:
            try:
                await self.revoke_user_permissions(role_name, [perm.uri])
            except aiohttp.ClientResponseError as exc:
                if exc.status == 400 and exc.message == "Operation has no effect":
                    pass
                else:
                    raise

    async def get_permissions(
        self, uname: str, *, expand_roles: bool = True
    ) -> Sequence[Permission]:
        if self._url is None:
            raise NotImplementedError("The method is not supported by Single-user mode")
        url = self._get_user_path(uname) + "/permissions"
        params = {}
        if not expand_roles:
            params["expand_roles"] = "false"
        async with self._request("GET", url, params=params) as resp:
            payload = await resp.json()
            return [Permission(item["uri"], item["action"]) for item in payload]

    async def add_role(self, uname: str) -> None:
        if self._url is None:
            return
        await self.add_user(User(name=uname))

    async def remove_role(self, uname: str) -> None:
        if self._url is None:
            return
        url = self._get_user_path(uname)
        try:
            async with self._request("DELETE", url):
                pass
        except aiohttp.ClientResponseError as exc:
            if exc.status != 404:
                raise

    async def delete_user(self, name: str, token: Optional[str] = None) -> None:
        if self._url is None:
            return
        path = self._get_user_path(name)
        headers = self._generate_headers(token)
        async with self._request("DELETE", path, headers=headers):
            pass  # use context manager to release response earlier


async def _raise_for_status(resp: aiohttp.ClientResponse) -> None:
    if 400 <= resp.status:
        details: str
        try:
            obj = await resp.json()
        except asyncio.CancelledError:
            raise
        except Exception:
            # ignore any error with reading message body
            details = resp.reason  # type: ignore
        else:
            try:
                details = obj["error"]
            except KeyError:
                details = str(obj)
        raise aiohttp.ClientResponseError(
            resp.request_info,
            resp.history,
            status=resp.status,
            message=details,
            headers=resp.headers,
        )


_action_order = {
    a: i for i, a in enumerate(("deny", "list", "read", "write", "manage"))
}


def _action_to_order(action: str) -> int:
    try:
        return _action_order[action]
    except KeyError:
        raise ValueError(f"invalid action: {action!r}") from None


def check_action_allowed(actual: str, requested: str) -> bool:
    return _action_to_order(actual) >= _action_to_order(requested)
