# Made by Sn0w8ird

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Union


def b64_encode(data: Union[str, bytes]) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.b64encode(raw).decode("ascii")


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def sha256_hex(content: Union[str, bytes]) -> str:
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(raw).hexdigest()


def random_token(nbytes: int = 16) -> str:
    return secrets.token_hex(nbytes)
