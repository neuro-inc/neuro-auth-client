import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Sequence

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
    clusters: List[Cluster] = field(default_factory=list)


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


@dataclass
class ClientAccessSubTreeView:
    action: str
    children: Dict[str, "ClientAccessSubTreeView"]

    @classmethod
    def _from_json(cls, json_as_dict: Dict[str, Any]) -> "ClientAccessSubTreeView":
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
    path: str
    sub_tree: ClientAccessSubTreeView

    @classmethod
    def _from_json(cls, json_as_dict: Dict[str, Any]) -> "ClientSubTreeViewRoot":
        subtree_path = json_as_dict["path"]
        sub_tree = ClientAccessSubTreeView._from_json(json_as_dict)
        return ClientSubTreeViewRoot(subtree_path, sub_tree)


class AuthClient:
    def __init__(
        self,
        url: URL,
        token: str,
        trace_configs: Optional[List[aiohttp.TraceConfig]] = None,
    ) -> None:
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
        if path.startswith("/"):
            path = path[1:]
        return self._url / path

    def _serialize_quota(self, quota: Quota) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
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

    async def ping(self) -> None:
        async with self._request("GET", "/api/v1/ping") as resp:
            txt = await resp.text()
            assert txt == "Pong"

    async def secured_ping(self, token: Optional[str] = None) -> None:
        path = "/api/v1/secured-ping"
        headers = self._generate_headers(token)
        async with self._request("GET", path, headers=headers) as resp:
            txt = await resp.text()
            assert txt == "Secured Pong"

    def _serialize_user(self, user: User) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"name": user.name}
        if user.clusters:
            payload["clusters"] = [self._serialize_cluster(c) for c in user.clusters]
        if user.email:
            payload["email"] = user.email
        return payload

    def _serialize_cluster(self, cluster: Cluster) -> Dict[str, Any]:
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
        path = self._get_user_path(user.name)
        headers = self._generate_headers(token)
        payload = self._serialize_user(user)
        async with self._request("PUT", path, headers=headers, json=payload):
            pass  # use context manager to release response earlier

    async def get_user(self, name: str, token: Optional[str] = None) -> User:
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

    def _deserialize_cluster(self, payload: Dict[str, Any]) -> Cluster:
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
        self, name: str, permissions: Sequence[Permission], token: Optional[str] = None
    ) -> bool:
        missing = await self.get_missing_permissions(name, permissions, token)
        return not missing

    async def get_missing_permissions(
        self, name: str, permissions: Sequence[Permission], token: Optional[str] = None
    ) -> Sequence[Permission]:
        assert permissions, "No permissions passed"
        path = self._get_user_path(name) + "/permissions/check"
        headers = self._generate_headers(token)
        payload: List[Dict[str, Any]] = [asdict(p) for p in permissions]
        async with self._request(
            "POST", path, headers=headers, json=payload, raise_for_status=False
        ) as resp:
            if resp.status not in (200, 403):
                await _raise_for_status(resp)
            data = await resp.json()
            if "missing" not in data:
                assert resp.status == 403, f"unexpected response {resp.status}: {data}"
                await _raise_for_status(resp)

            return [self._permission_from_primitive(p) for p in data["missing"]]

    def _permission_from_primitive(self, perm: Dict[str, str]) -> Permission:
        return Permission(uri=perm["uri"], action=perm["action"])

    async def get_permissions_tree(
        self, name: str, resource: str, depth: Optional[int] = None
    ) -> ClientSubTreeViewRoot:
        url = self._get_user_path(name) + "/permissions/tree"
        req_params: Dict[str, Any] = {"uri": resource}
        if depth is not None:
            req_params["depth"] = depth
        async with self._request("GET", url, params=req_params) as resp:
            payload = await resp.json()
            tree = ClientSubTreeViewRoot._from_json(payload)
            return tree

    async def grant_user_permissions(
        self, name: str, permissions: Sequence[Permission], token: Optional[str] = None
    ) -> None:
        path = self._get_user_path(name) + "/permissions"
        headers = self._generate_headers(token)
        payload: List[Dict[str, str]] = [asdict(p) for p in permissions]
        async with self._request("POST", path, headers=headers, json=payload) as resp:
            status = resp.status
            assert status == HTTPCreated.status_code, f"unexpected response: {status}"

    async def revoke_user_permissions(
        self, name: str, resources_uris: Sequence[str], token: Optional[str] = None
    ) -> None:
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
        path = self._get_user_path(name) + "/token"
        headers = self._generate_headers(token)
        if new_token_uri:
            data = dict(uri=new_token_uri)
        else:
            data = dict()
        async with self._request("POST", path, headers=headers, json=data) as resp:
            payload = await resp.json()
            return payload["access_token"]


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
