from typing import Optional

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, Response

from . import config

_serializer = URLSafeTimedSerializer(config.SECRET_KEY, salt="phishsurf-auth")


def make_session_cookie_value() -> str:
    return _serializer.dumps({"ok": True})


def verify_session_cookie(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        data = _serializer.loads(value, max_age=config.COOKIE_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    return bool(data.get("ok"))


def is_authenticated(request: Request) -> bool:
    return verify_session_cookie(request.cookies.get(config.COOKIE_NAME))


def set_auth_cookie(response: Response) -> None:
    response.set_cookie(
        config.COOKIE_NAME,
        make_session_cookie_value(),
        max_age=config.COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )


def clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(config.COOKIE_NAME)
