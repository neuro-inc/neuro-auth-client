from typing import Callable, Dict

from aiohttp.hdrs import AUTHORIZATION
from aiohttp.helpers import BasicAuth
from aiohttp.test_utils import make_mocked_request

from auth_server.config import SecurityConfig
from auth_server.security import JWT_IDENTITY_CLAIM, JWTCodec
from neuro_auth_client import AuthClient, Cluster, Permission, User
from neuro_auth_client.bearer_auth import BearerAuth
from neuro_auth_client.security import AuthPolicy, AuthScheme, IdentityPolicy


class TestIdentityPolicy:
    async def test_no_auth_header(self) -> None:
        policy = IdentityPolicy(auth_scheme=AuthScheme.BASIC)
        request = make_mocked_request("GET", "/")
        identity = await policy.identify(request)
        assert identity is None

    async def test_basic(self) -> None:
        policy = IdentityPolicy(auth_scheme=AuthScheme.BASIC)
        headers: Dict[str, str] = {
            AUTHORIZATION: BasicAuth(login="whatever", password="JWT").encode()
        }
        request = make_mocked_request("GET", "/", headers=headers)
        identity = await policy.identify(request)
        assert identity == "JWT"

    async def test_bearer(self) -> None:
        policy = IdentityPolicy(auth_scheme=AuthScheme.BEARER)
        headers: Dict[str, str] = {AUTHORIZATION: BearerAuth(token="JWT").encode()}
        request = make_mocked_request("GET", "/", headers=headers)
        identity = await policy.identify(request)
        assert identity == "JWT"


class TestAuthPolicy:
    async def test_authorized_user_unknown_user(
        self, client: AuthClient, token_factory: Callable[[str], str]
    ) -> None:
        unknown_token = token_factory("unknown")
        policy = AuthPolicy(auth_client=client)
        user = await policy.authorized_user(unknown_token)
        assert user is None

    async def test_authorized_userid_unknown_user(
        self, client: AuthClient, token_factory: Callable[[str], str]
    ) -> None:
        unknown_token = token_factory("unknown")
        policy = AuthPolicy(auth_client=client)
        userid = await policy.authorized_userid(unknown_token)
        assert userid is None

    async def test_authorized_user_malformed_token(
        self, client: AuthClient, admin_token: str
    ) -> None:
        policy = AuthPolicy(auth_client=client)
        user = await policy.authorized_user("malformed")
        assert user is None

    async def test_authorized_userid_malformed_token(
        self, client: AuthClient, admin_token: str
    ) -> None:
        policy = AuthPolicy(auth_client=client)
        userid = await policy.authorized_userid("malformed")
        assert userid is None

    async def test_authorized_user_new_identity_claim(
        self, client: AuthClient, security_config: SecurityConfig
    ) -> None:
        codec = JWTCodec.from_config(security_config)
        payload = {JWT_IDENTITY_CLAIM: "admin"}
        admin_token = codec.encode(payload)
        policy = AuthPolicy(auth_client=client)
        user = await policy.authorized_user(admin_token)
        assert user == User(name="admin", clusters=[Cluster(name="default")])

    async def test_authorized_userid_new_identity_claim(
        self, client: AuthClient, security_config: SecurityConfig
    ) -> None:
        codec = JWTCodec.from_config(security_config)
        payload = {JWT_IDENTITY_CLAIM: "admin"}
        admin_token = codec.encode(payload)
        policy = AuthPolicy(auth_client=client)
        userid = await policy.authorized_userid(admin_token)
        assert userid == "admin"

    async def test_authorized_user(self, client: AuthClient, admin_token: str) -> None:
        policy = AuthPolicy(auth_client=client)
        user = await policy.authorized_user(admin_token)
        assert user == User(name="admin", clusters=[Cluster(name="default")])

    async def test_authorized_userid(
        self, client: AuthClient, admin_token: str
    ) -> None:
        policy = AuthPolicy(auth_client=client)
        userid = await policy.authorized_userid(admin_token)
        assert userid == "admin"

    async def test_permits(self, client: AuthClient, admin_token: str) -> None:
        policy = AuthPolicy(auth_client=client)
        permissions = [Permission(uri="user:", action="manage")]
        assert await policy.permits(admin_token, "", permissions)

    async def test_permits_malformed_token(self, client: AuthClient) -> None:
        policy = AuthPolicy(auth_client=client)
        permissions = [Permission(uri="user:", action="manage")]
        assert not await policy.permits("malformed", "", permissions)

    async def test_permits_forbidden(self, client: AuthClient, user_token: str) -> None:
        await client.add_user(User("user"))
        policy = AuthPolicy(auth_client=client)
        permissions = [Permission(uri="storage:", action="manage")]
        assert not await policy.permits(user_token, "", permissions)

    def test_get_user_name_from_identity(
        self, client: AuthClient, admin_token: str
    ) -> None:
        policy = AuthPolicy(auth_client=client)
        userid = policy.get_user_name_from_identity(admin_token)
        assert userid == "admin"

    def test_get_user_name_from_identity_malformed(self, client: AuthClient) -> None:
        policy = AuthPolicy(auth_client=client)
        userid = policy.get_user_name_from_identity("malformed")
        assert userid is None
