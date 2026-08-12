#!/usr/bin/env python3
"""Shared policy for the small set of user-facing audit events."""

import datetime as dt
import hashlib
import os
from typing import Mapping, Optional, Tuple

AUDIT_ACTIONS = frozenset({"read", "write", "move", "delete"})

OPERATION_ACTIONS = {
    "read": "read",
    "pread": "read",
    "pread_recv": "read",
    "pread_send": "read",
    "sendfile": "read",
    "offload_read_recv": "read",
    "offload_read_send": "read",
    "write": "write",
    "pwrite": "write",
    "pwrite_recv": "write",
    "pwrite_send": "write",
    "recvfile": "write",
    "offload_write_recv": "write",
    "offload_write_send": "write",
    "renameat": "move",
    "rename": "move",
    "unlinkat": "delete",
    "unlink": "delete",
    "rmdir": "delete",
}

def action_for(operation: str) -> Optional[str]:
    return OPERATION_ACTIONS.get(operation.strip().casefold())

def skipped_user_suffixes() -> Tuple[str, ...]:
    raw = os.getenv("AUDIT_SKIP_USER_SUFFIXES", "_svc,_ServiceAcc")
    return tuple(
        suffix.strip().casefold()
        for suffix in raw.split(",")
        if suffix.strip()
    )

def account_name(user: str) -> str:
    account = user.strip().rsplit("\\", 1)[-1]
    return account.split("@", 1)[0]

def skip_user(user: str) -> bool:
    account = account_name(user).casefold()
    return any(account.endswith(suffix) for suffix in skipped_user_suffixes())

ReadEventKey = Tuple[str, ...]

def read_deduplication_key(event: Mapping[str, object]) -> Optional[ReadEventKey]:
    if str(event.get("action", "")).casefold() != "read":
        return None
    try:
        timestamp = dt.datetime.fromisoformat(
            str(event.get("timestamp", "")).replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
        second = (
            timestamp.astimezone(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
    except ValueError:
        second = str(event.get("timestamp", ""))

    success = bool(event.get("success", False))
    return (
        second,
        str(event.get("user", "")),
        str(event.get("clientIp", "")),
        str(event.get("share", "")),
        str(event.get("path", "")),
        "success" if success else "failure",
        "" if success else str(event.get("result", "")),
    )

def read_deduplication_fingerprint(
    event: Mapping[str, object]
) -> Optional[bytes]:
    key = read_deduplication_key(event)
    if key is None:
        return None
    digest = hashlib.blake2b(digest_size=16)
    for value in key:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()

def read_deduplication_fingerprint_values(
    timestamp: object,
    user: object,
    client_ip: object,
    share: object,
    path: object,
    success: object,
    result: object,
) -> bytes:
    """Fingerprint legacy SQLite columns with the live-ingest policy."""
    fingerprint = read_deduplication_fingerprint({
        "action": "read",
        "timestamp": timestamp,
        "user": user,
        "clientIp": client_ip,
        "share": share,
        "path": path,
        "success": bool(success),
        "result": result,
    })
    assert fingerprint is not None
    return fingerprint
