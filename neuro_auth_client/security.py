from collections.abc import Sequence
from enum import Enum, StrEnum
from typing import Any, Optional, Union

from aiohttp.client_exceptions import ClientResponseError
from aiohttp.hdrs import AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL
from aiohttp.helpers import BasicAuth
from aiohttp.web import Application, Request, StreamResponse
from aiohttp_security import AbstractAuthorizationPolicy, AbstractIdentityPolicy, setup
from jose import jwt
from jose.exceptions import JWTError

from .bearer_auth import BearerAuth
from .client import AuthClient, Permission, User

JWT_IDENTITY_CLAIM = "https://platform.neuromation.io/user"
JWT_IDENTITY_CLAIM_OPTIONS = ("identity", JWT_IDENTITY_CLAIM)
JWT_KIND_CLAIM = "https://platform.neuromation.io/kind"
# exists only for tokens of cluster services
JWT_CLUSTER_CLAIM = "https://platform.neuromation.io/cluster"

NEURO_AUTH_TOKEN_QUERY_PARAM = "neuro-auth-token"
WS_BEARER = "bearer.apolo.us-"


class AuthScheme(StrEnum):
    BASIC = "basic"
    BEARER = "bearer"


class Kind(StrEnum):
    CONTROL_PLANE = "control_plane"
    CLUSTER = "cluster"
    USER = "user"


class IdentityError(ValueError):
    """Identity error"""


class IdentityPolicy(AbstractIdentityPolicy):
    def __init__(
        self,
        auth_scheme: AuthScheme = AuthScheme.BEARER,
        default_identity: Optional[str] = None,
    ) -> None:
        self._auth_scheme = auth_scheme
        self._default_identity = default_identity

    async def identify(self, request: Request) -> Optional[str]:
        header_identity = request.headers.get(AUTHORIZATION)

        if header_identity is None:
            ws_identity = self._extract_ws_identity(request)
            query_identity = request.query.get(NEURO_AUTH_TOKEN_QUERY_PARAM)
            return ws_identity or query_identity or self._default_identity

        if self._auth_scheme == AuthScheme.BASIC:
            identity = BasicAuth.decode(header_identity).password
        else:
            identity = BearerAuth.decode(header_identity).token

        return identity

    async def remember(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        pass

    async def forget(
        self, request: Request, response: StreamResponse
    ) -> None:  # pragma: no cover
        pass

    def _extract_ws_identity(self, request: Request) -> str | None:
        ws_subprotocol = request.headers.get(SEC_WEBSOCKET_PROTOCOL)
        if ws_subprotocol is not None:
            for part in ws_subprotocol.strip().split(" "):
                if part.lower().startswith(WS_BEARER):
                    ws_identity = part[len(WS_BEARER) :]
                    return ws_identity
        return None


class AuthPolicy(AbstractAuthorizationPolicy):
    def __init__(self, auth_client: AuthClient) -> None:
        self._auth_client = auth_client

    def get_user_name_from_identity(self, identity: str | None) -> Optional[str]:
        if identity is None or self._auth_client.is_anonymous_access_allowed:
            return "user"

        try:
            claims = jwt.get_unverified_claims(identity)
            for identity_claim in JWT_IDENTITY_CLAIM_OPTIONS:
                if identity_claim in claims:
                    return claims[identity_claim]
            return None
        except JWTError:
            return None

    async def authorized_user(self, identity: str) -> Optional[User]:
        """Retrieve authorized user object (works same as authorized_userid)

        Return the user object identified by the identity
        or 'None' if no user exists related to the identity.
        """
        name = self.get_user_name_from_identity(identity)
        if not name:
            return None
        try:
            # NOTE: here we make a call to the auth service on behalf of the
            # actual user, not a service.
            return await self._auth_client.get_user(name, token=identity)
        except ClientResponseError:
            return None

    async def authorized_userid(self, identity: str) -> Optional[str]:
        user = await self.authorized_user(identity)
        if user:
            return user.name
        return None

    def get_kind(self, identity: str) -> Kind:
        try:
            claims = jwt.get_unverified_claims(identity)
            return Kind(claims.get(JWT_KIND_CLAIM, Kind.USER))
        except JWTError:
            return Kind.USER

    def get_cluster(self, identity: str) -> str:
        claims = jwt.get_unverified_claims(identity)
        kind = claims.get(JWT_KIND_CLAIM, Kind.USER)
        if kind != Kind.CLUSTER:
            raise IdentityError(
                f"identity has unexpected kind '{kind}', expected 'cluster'"
            )
        ret = claims.get(JWT_CLUSTER_CLAIM)
        if not ret:
            raise IdentityError(
                f"identity has kind 'cluster', but has no {JWT_CLUSTER_CLAIM} claim"
            )
        return ret

    async def permits(
        self,
        identity: str | None,
        permission: str | Enum,
        context: Any = None,
    ) -> bool:
        name = self.get_user_name_from_identity(identity)
        if not name:
            return False
        return await self._auth_client.check_user_permissions(name, context)

    async def get_missing_permissions(
        self,
        user_name: str,
        permissions: Sequence[Union[Permission, Sequence[Permission]]],
    ) -> Sequence[Permission]:
        return await self._auth_client.get_missing_permissions(user_name, permissions)


async def setup_security(
    app: Application,
    auth_client: AuthClient,
    auth_scheme: AuthScheme = AuthScheme.BEARER,
) -> None:  # pragma: no cover
    if auth_client.is_anonymous_access_allowed:
        identity_policy = IdentityPolicy(
            auth_scheme=auth_scheme, default_identity="user"
        )
    else:
        identity_policy = IdentityPolicy(auth_scheme=auth_scheme)
    auth_policy = AuthPolicy(auth_client=auth_client)
    setup(app, identity_policy, auth_policy)
