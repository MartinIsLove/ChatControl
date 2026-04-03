import time, threading
from fastapi import HTTPException

LOGIN_BACKOFF_STEP_REQUESTS = 5
LOGIN_BACKOFF_BASE_SECONDS = 60

_login_rate_limit_lock = threading.Lock()
_login_rate_limit_store = {}


def _enforce_login_rate_limit(client_ip: str):
    now = time.time()
    key = client_ip

    with _login_rate_limit_lock:
        bucket = _login_rate_limit_store.get(key, {"failed_attempts": 0, "blocked_until": 0.0})

        if bucket["blocked_until"] > now:
            seconds_left = int(bucket["blocked_until"] - now)
            raise HTTPException(
                status_code=429,
                detail=f"Troppi tentativi di login. Riprova tra {max(seconds_left, 1)} secondi.",
            )

def _register_login_failure(client_ip: str):
    now = time.time()
    key = client_ip
    multiplier = 1
    with _login_rate_limit_lock:
        bucket = _login_rate_limit_store.get(key, {"failed_attempts": 0, "blocked_until": 0.0})
        bucket["failed_attempts"] += 1
        if bucket["failed_attempts"] <= 6:
            multiplier = ((bucket["failed_attempts"] - 1) // LOGIN_BACKOFF_STEP_REQUESTS)
        else:
            multiplier = 2 ** (bucket["failed_attempts"] - 6)

        if multiplier >= 1:
            wait_seconds = LOGIN_BACKOFF_BASE_SECONDS * multiplier
            bucket["blocked_until"] = now + wait_seconds

        _login_rate_limit_store[key] = bucket


def _reset_login_rate_limit(client_ip: str):
    key = client_ip
    with _login_rate_limit_lock:
        _login_rate_limit_store.pop(key, None)
