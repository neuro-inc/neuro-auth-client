import pytest

from neuro_auth_client.bearer_auth import BearerAuth


class TestBearerAuth:
    def test_decode_unexpected_scheme(self) -> None:
        with pytest.raises(ValueError, match="Unexpected authorization scheme"):
            BearerAuth.decode("Basic credentials")

    @pytest.mark.parametrize("header_value", ("Bearer", "Bearer "))
    def test_decode_no_credentials(self, header_value: str) -> None:
        with pytest.raises(ValueError, match="No credentials"):
            BearerAuth.decode(header_value)

    @pytest.mark.parametrize("token", ("token", "to ken"))
    def test_decode(self, token: str) -> None:
        auth = BearerAuth.decode("Bearer " + token)
        assert auth == BearerAuth(token=token)

    def test_encode(self) -> None:
        assert BearerAuth(token="token").encode() == "Bearer token"
