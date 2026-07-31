#!/usr/bin/env python3
"""End-to-end checks for the disposable preview domain and file server."""

import base64
import datetime as dt
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Optional


ENGINE = os.environ["PREVIEW_ENGINE"]
FILES_CONTAINER = os.environ["PREVIEW_FILES_CONTAINER"]
CLIENT_CONTAINER = os.environ["PREVIEW_CLIENT_CONTAINER"]
BACKUP_CONTAINER = os.environ["PREVIEW_BACKUP_CONTAINER"]
CA_ROOT = os.environ["PREVIEW_CA_ROOT"]
HTTPS_PORT = int(os.environ["PREVIEW_HTTPS_PORT"])
REALM = os.environ["PREVIEW_REALM"]
WORKGROUP = os.environ["PREVIEW_WORKGROUP"]
DNS_DOMAIN = os.environ["PREVIEW_DNS_DOMAIN"]
DOMAIN_SID = os.environ["PREVIEW_DOMAIN_SID"]
ADMIN_USER = os.environ["PREVIEW_ADMIN_USER"]
ADMIN_PASSWORD = os.environ["PREVIEW_ADMIN_PASSWORD"]
USER_PASSWORD = os.environ["PREVIEW_USER_PASSWORD"]
HTTPS_HOST = os.environ["PREVIEW_HTTPS_HOST"]
BASE_URL = f"https://{HTTPS_HOST}:{HTTPS_PORT}"
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def preview_getaddrinfo(host, port, *args, **kwargs):
    if host == HTTPS_HOST:
        host = "127.0.0.1"
    return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)


socket.getaddrinfo = preview_getaddrinfo
TLS_CONTEXT = ssl.create_default_context(cafile=CA_ROOT)
HTTP_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=TLS_CONTEXT),
)


@dataclass
class Response:
    status: int
    headers: object
    body: bytes

    def json(self):
        return json.loads(self.body.decode("utf-8"))


def fail(message: str) -> None:
    raise AssertionError(message)


def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def announce(message: str) -> None:
    print(f"[e2e] {message}", flush=True)


def engine_run(*args: str, check_result: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [ENGINE, *args], capture_output=True, text=True, check=False
    )
    if check_result and result.returncode != 0:
        output = result.stderr.strip() or result.stdout.strip()
        fail(f"container command failed ({' '.join(args)}): {output}")
    return result


def http(
    path: str,
    *,
    method: str = "GET",
    value: Optional[Dict[str, object]] = None,
    token: str = "",
) -> Response:
    body = None
    headers = {"Accept": "application/json"}
    if value is not None:
        body = json.dumps(value).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{BASE_URL}{path}", data=body, headers=headers, method=method
    )
    try:
        with HTTP_OPENER.open(request, timeout=30) as response:
            return Response(response.status, response.headers, response.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.headers, exc.read())


def eventually(
    description: str,
    callback: Callable[[], object],
    predicate: Callable[[object], bool],
    timeout: float = 90,
    interval: float = 1,
):
    deadline = time.monotonic() + timeout
    last_value = None
    last_error: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            last_value = callback()
            if predicate(last_value):
                return last_value
        except Exception as exc:  # pylint: disable=broad-except
            last_error = exc
        time.sleep(interval)
    detail = f"; last value={last_value!r}"
    if last_error is not None:
        detail += f"; last error={last_error}"
    fail(f"timed out waiting for {description}{detail}")


def decode_jwt_payload(token: str) -> Dict[str, object]:
    parts = token.split(".")
    check(len(parts) == 3, "login did not return a compact JWT")
    padding = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + padding))


def flatten_members(nodes):
    values = []
    for node in nodes:
        values.append((node.get("type"), node.get("sam"), node.get("name")))
        values.extend(flatten_members(node.get("members", [])))
    return values


def query_path(path: str, params: Dict[str, str]) -> str:
    return f"{path}?{urllib.parse.urlencode(params)}"


def main() -> int:
    announce("TLS chain, hostname, public health, and browser security headers")
    health = http("/healthz")
    check(health.status == 200 and health.json() == {"status": "ok"}, "health check failed")
    index = http("/")
    check(index.status == 200 and b'Dateiserver-Verwaltung' in index.body, "German web shell was not served")
    check(b'<html lang="de">' in index.body, "web shell language is not German")
    styles = http("/assets/styles.css")
    check(b"[hidden]" in styles.body and b"display: none !important" in styles.body, "hidden views can be made visible by author CSS")
    script = http("/assets/app.js")
    check(b"getUTCHours()" in script.body and b" UTC`" in script.body, "UI does not format timestamps explicitly in UTC")
    check(b"localTime" not in script.body and b"eyebrow" not in script.body, "obsolete local-time or decorative UI code remains")
    check(b"brand-mark" not in index.body, "decorative brand mark remains")
    check("max-age=" in index.headers.get("Strict-Transport-Security", ""), "HSTS missing")
    check("default-src 'self'" in index.headers.get("Content-Security-Policy", ""), "CSP missing")
    with socket.create_connection(("localhost", HTTPS_PORT), timeout=10) as raw:
        with TLS_CONTEXT.wrap_socket(raw, server_hostname=HTTPS_HOST) as secured:
            certificate = secured.getpeercert()
    sans = {value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"}
    check(HTTPS_HOST in sans, f"issued certificate does not cover {HTTPS_HOST}")
    check(certificate.get("issuer") != certificate.get("subject"), "web certificate is self-signed instead of CA-issued")

    announce("JWT boundary, real Kerberos credentials, and Domain Admin authorization")
    unauthenticated = http("/api/session")
    check(unauthenticated.status == 401, "protected API accepted an anonymous request")
    non_admin = http(
        "/api/login",
        method="POST",
        value={"username": "alice", "password": USER_PASSWORD},
    )
    check(non_admin.status == 401, "valid non-admin domain user was allowed into the UI")
    wrong_password = http(
        "/api/login",
        method="POST",
        value={"username": ADMIN_USER, "password": "wrong-password"},
    )
    check(wrong_password.status == 401, "invalid admin password was accepted")
    login = http(
        "/api/login",
        method="POST",
        value={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
    )
    check(login.status == 200, f"Domain Admin login failed: {login.body!r}")
    login_payload = login.json()
    token = str(login_payload.get("token", ""))
    claims = decode_jwt_payload(token)
    check(claims.get("iss") == "ad-file-server-web", "JWT issuer is wrong")
    check(claims.get("aud") == "domain-admins", "JWT audience is wrong")
    check(claims.get("role") == "domain-admin", "JWT role is wrong")
    check(claims.get("sub") == f"{WORKGROUP}\\{ADMIN_USER}", "JWT subject is wrong")
    cookie = login.headers.get("Set-Cookie", "")
    for attribute in ("HttpOnly", "Secure", "SameSite=Strict"):
        check(attribute in cookie, f"session cookie is missing {attribute}")
    session = http("/api/session", token=token)
    check(session.status == 200 and session.json().get("user") == claims["sub"], "Bearer JWT was not accepted")
    check(http("/api/session", token=f"{token}corrupt").status == 401, "corrupt JWT was accepted")
    readonly = http("/api/groups", method="POST", value={}, token=token)
    check(readonly.status == 404, "a mutation-like API method was accepted")

    announce("AD trust, nested group tree, folders, and domain membership")
    engine_run("exec", FILES_CONTAINER, "wbinfo", "-t")
    admin_identity = engine_run(
        "exec", FILES_CONTAINER, "wbinfo", "--name-to-sid", f"{WORKGROUP}\\{ADMIN_USER}"
    )
    admin_sid = admin_identity.stdout.split()[0]
    admin_sids = engine_run(
        "exec", FILES_CONTAINER, "wbinfo", "--user-sids", admin_sid
    )
    check(f"{DOMAIN_SID}-512" in admin_sids.stdout, "preview admin SID set lacks Domain Admins")
    groups_response = http("/api/groups", token=token)
    check(groups_response.status == 200, f"group endpoint failed: {groups_response.body!r}")
    groups_payload = groups_response.json()
    groups = {row["name"]: row for row in groups_payload.get("groups", [])}
    check({"Finance", "Engineering", "Projects"}.issubset(groups), f"seed groups missing: {sorted(groups)}")
    check(groups["Finance"]["folder"] == "Finance", "Finance group/folder mapping is wrong")
    finance_nodes = flatten_members(groups["Finance"].get("members", []))
    check(any(kind == "group" and sam == "Finance_Analysts" for kind, sam, _ in finance_nodes), "nested Finance Analysts group missing")
    check({"alice", "bob"}.issubset({sam for kind, sam, _ in finance_nodes if kind == "user"}), "Finance users missing")
    project_nodes = flatten_members(groups["Projects"].get("members", []))
    check({"alice", "bob", "carol", "dave", "eve"}.issubset({sam for kind, sam, _ in project_nodes if kind == "user"}), "transitive Project membership is incomplete")

    announce("SMB authorization and real share reads/writes")
    alice_access = engine_run(
        "exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
        "-U", f"{WORKGROUP}\\alice%{USER_PASSWORD}", "-c", "cd Finance; ls",
        check_result=False,
    )
    check(alice_access.returncode == 0, f"Alice cannot access Finance: {alice_access.stderr}")
    dave_denied = engine_run(
        "exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
        "-U", f"{WORKGROUP}\\dave%{USER_PASSWORD}", "-c", "cd Finance; ls",
        check_result=False,
    )
    check(dave_denied.returncode != 0, "unrelated user Dave can access Finance")
    admin_access = engine_run(
        "exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
        "-U", f"{WORKGROUP}\\{ADMIN_USER}%{ADMIN_PASSWORD}", "-c", "cd Finance; ls",
        check_result=False,
    )
    check(admin_access.returncode == 0, "Domain Admin cannot inspect Finance")

    announce("group, Private, and FSLogix size accounting")
    storage = http("/api/storage", token=token)
    check(storage.status == 200, f"storage endpoint failed: {storage.body!r}")
    storage_payload = storage.json()
    storage_groups = {row["name"]: int(row["bytes"]) for row in storage_payload.get("groups", [])}
    check(storage_groups.get("Finance", 0) >= 1024 * 1024, "Finance usage was not scanned")
    check(storage_groups.get("Engineering", 0) >= 1024 * 1024, "Engineering usage was not scanned")
    users = {row["name"].casefold(): row for row in storage_payload.get("users", [])}
    check(int(users.get("alice", {}).get("privateBytes", 0)) > 0, "Alice Private usage missing")
    check(int(users.get("alice", {}).get("fslogixBytes", 0)) > 0, "Alice FSLogix usage missing")
    check(int(storage_payload.get("totals", {}).get("dataBytes", 0)) > 0, "Data total is empty")

    announce("live Samba audit ingestion, filters, facets, and pagination")
    activity = eventually(
        "live alice audit records",
        lambda: http(query_path("/api/activity", {"user": "alice", "limit": "5"}), token=token),
        lambda response: response.status == 200 and response.json().get("matched", 0) >= 2,
        timeout=60,
    )
    activity_payload = activity.json()
    check(all("alice" in str(event.get("user", "")).casefold() for event in activity_payload["events"]), "activity user filter leaked unrelated events")
    check("Data" in activity_payload.get("facets", {}).get("shares", []), "activity share facets missing Data")
    one_event = http(query_path("/api/activity", {"limit": "1"}), token=token).json()
    check(len(one_event.get("events", [])) == 1, "activity limit was ignored")
    check(one_event.get("nextCursor") is not None, "activity pagination cursor missing")

    announce("closed daily log compression and querying gzip history")
    old_day = (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=2)).isoformat()
    eventually(
        "historical audit gzip",
        lambda: engine_run(
            "exec", FILES_CONTAINER, "test", "-f", f"/state/audit/{old_day}.jsonl.gz",
            check_result=False,
        ).returncode,
        lambda returncode: returncode == 0,
        timeout=30,
    )
    archived = http(
        query_path(
            "/api/activity",
            {"from": old_day, "to": old_day, "user": "archived-user", "limit": "10"},
        ),
        token=token,
    )
    check(archived.status == 200 and archived.json().get("matched") == 1, "compressed audit history is not searchable")

    announce("real rsync backup, status API, log tail, and remote completion marker")
    backup = eventually(
        "completed backup",
        lambda: http("/api/backup", token=token),
        lambda response: response.status == 200 and response.json().get("state") in {"completed", "failed"},
        timeout=240,
        interval=2,
    )
    backup_payload = backup.json()
    check(backup_payload.get("state") == "completed", f"backup failed: {backup_payload}")
    check(float(backup_payload.get("percent", 0)) == 100.0, "completed backup is not at 100%")
    check(any("completed" in line.casefold() for line in backup_payload.get("log", [])), "backup completion absent from log tail")
    marker = engine_run(
        "exec", BACKUP_CONTAINER, "sh", "-ec",
        "find /backup/fileserver/snapshots -name .backup_complete -type f | grep -q .",
        check_result=False,
    )
    check(marker.returncode == 0, "backup target has no completed snapshot marker")

    announce("overview and system health aggregation")
    overview = http("/api/overview", token=token)
    check(overview.status == 200 and overview.json().get("activeGroups") == 3, "overview group count is wrong")
    system = http("/api/system", token=token)
    check(system.status == 200, f"system endpoint failed: {system.body!r}")
    system_payload = system.json()
    check(system_payload.get("checks", {}).get("domainTrust") is True, "system reports broken AD trust")
    check(system_payload.get("checks", {}).get("sambaConfig") is True, "system reports invalid Samba config")
    check(system_payload.get("tls", {}).get("sans"), "system TLS summary is empty")
    check(system_payload.get("audit", {}).get("days", 0) >= 2, "system audit archive summary is incomplete")

    logout = http("/api/logout", method="POST", value={}, token=token)
    check(logout.status == 200 and "Max-Age=0" in logout.headers.get("Set-Cookie", ""), "logout did not clear session cookie")

    announce("PASS: all end-to-end assertions succeeded")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[e2e] FAIL: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
