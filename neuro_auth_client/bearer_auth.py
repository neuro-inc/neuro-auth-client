from dataclasses import dataclass


@dataclass(frozen=True)
class BearerAuth:
    """Result of parsing the Bearer HTTP Authorization header.

    Analogous to `aiohttp.helpers.BasicAuth`.
    """

    token: str

    @classmethod
    def decode(cls, header_value: str) -> "BearerAuth":
        try:
            auth_scheme, token = header_value.split(" ", 1)
        except ValueError:
            raise ValueError("No credentials")
        if auth_scheme.lower() != "bearer":
            raise ValueError("Unexpected authorization scheme")
        if not token:
            raise ValueError("No credentials")
        return cls(token=token)

    def encode(self) -> str:
        return "Bearer " + self.token
