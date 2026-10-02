#!/usr/bin/env python3
"""End-to-end checks for the disposable preview domain and file server."""

import base64
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
    check(
        b"Sicherung jetzt starten" in script.body
        and b"Freigaben jetzt abgleichen" in script.body
        and b'href="/reconciliation"' in index.body,
        "manual actions or the top-level reconciliation navigation are missing",
    )
    check(b"localTime" not in script.body and b"eyebrow" not in script.body, "obsolete local-time or decorative UI code remains")
    report_script = http("/assets/report.mjs")
    check(
        report_script.status == 200
        and b"compiler.pdf({mainContent:" in report_script.body
        and b"getUTCHours()" in report_script.body,
        "client-side Typst report module is missing or does not use UTC",
    )
    typst_script = http("/assets/vendor/typst/0.6.0-csp1/typst.mjs")
    check(
        typst_script.status == 200 and b"TypstSnippet" in typst_script.body,
        "vendored Typst browser wrapper is missing",
    )
    typst_wasm = http("/assets/vendor/typst/0.6.0-csp1/compiler.wasm")
    check(
        typst_wasm.status == 200
        and typst_wasm.body.startswith(b"\x00asm")
        and typst_wasm.headers.get("Content-Type") == "application/wasm",
        "vendored Typst compiler WASM is missing or has the wrong MIME type",
    )
    check(
        "immutable" in typst_wasm.headers.get("Cache-Control", ""),
        "large immutable Typst assets are not browser-cacheable",
    )
    typst_font = http("/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Regular.otf")
    check(
        typst_font.status == 200
        and typst_font.body.startswith(b"OTTO")
        and typst_font.headers.get("Content-Type") == "font/otf",
        "vendored Typst report font is missing or has the wrong MIME type",
    )
    check(b"brand-mark" not in index.body, "decorative brand mark remains")
    check("max-age=" in index.headers.get("Strict-Transport-Security", ""), "HSTS missing")
    csp = index.headers.get("Content-Security-Policy", "")
    check("default-src 'self'" in csp, "CSP missing")
    check(
        "script-src 'self' 'wasm-unsafe-eval'" in csp and "'unsafe-eval'" not in csp,
        "CSP does not narrowly permit the local WebAssembly compiler",
    )
    with socket.create_connection(("localhost", HTTPS_PORT), timeout=10) as raw:
        with TLS_CONTEXT.wrap_socket(raw, server_hostname=HTTPS_HOST) as secured:
            certificate = secured.getpeercert()
    sans = {value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"}
    check(HTTPS_HOST in sans, f"issued certificate does not cover {HTTPS_HOST}")
    check(certificate.get("issuer") != certificate.get("subject"), "web certificate is self-signed instead of CA-issued")

    announce("JWT boundary, real Kerberos credentials, and Domain Admin authorization")
    unauthenticated = http("/api/session")
    check(unauthenticated.status == 401, "protected API accepted an anonymous request")
    check(
        http("/api/actions/backup", method="POST", value={}).status == 401,
        "anonymous backup action was accepted",
    )
    check(
        http("/api/actions/reconciliation", method="POST", value={}).status == 401,
        "anonymous reconciliation action was accepted",
    )
    check(http("/api/trash").status == 401, "anonymous trash listing was accepted")
    check(
        http(
            "/api/trash/restore",
            method="POST",
            value={"id": "invalid"},
        ).status
        == 401,
        "anonymous trash restore was accepted",
    )
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
    check(all(kind == "user" for kind, _, _ in finance_nodes), "Finance still contains group assignments")
    check({"alice", "bob"}.issubset({sam for kind, sam, _ in finance_nodes if kind == "user"}), "Finance users missing")
    project_nodes = flatten_members(groups["Projects"].get("members", []))
    check({"alice", "bob", "carol", "dave", "eve", "frank"}.issubset({sam for kind, sam, _ in project_nodes if kind == "user"}), "transitive or primary-group Project membership is incomplete")
    check(all(kind == "user" for kind, _, _ in project_nodes), "Projects still contains group assignments")

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
    frank_projects = engine_run(
        "exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
        "-U", f"{WORKGROUP}\\frank%{USER_PASSWORD}", "-c", "cd Projects; ls",
        check_result=False,
    )
    check(frank_projects.returncode == 0, "primary Domain Users membership did not grant Projects access")
    admin_access = engine_run(
        "exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
        "-U", f"{WORKGROUP}\\{ADMIN_USER}%{ADMIN_PASSWORD}", "-c", "cd Finance; ls",
        check_result=False,
    )
    check(admin_access.returncode == 0, "Domain Admin cannot inspect Finance")
    direct_trash_access = engine_run(
        "exec",
        CLIENT_CONTAINER,
        "smbclient",
        f"//files.{DNS_DOMAIN}/Data",
        "-m",
        "SMB3",
        "-U",
        f"{WORKGROUP}\\alice%{USER_PASSWORD}",
        "-c",
        "cd .trash",
        check_result=False,
    )
    check(
        direct_trash_access.returncode != 0,
        "ordinary SMB user can browse the admin-managed trash repository",
    )

    announce("temporary and document-lock files bypass the recycle repository")
    transient_delete = engine_run(
        "exec",
        CLIENT_CONTAINER,
        "smbclient",
        f"//files.{DNS_DOMAIN}/Data",
        "-m",
        "SMB3",
        "-U",
        f"{WORKGROUP}\\alice%{USER_PASSWORD}",
        "-c",
        (
            "cd Finance; cd Reports; "
            "put /tmp/live-note.txt 713A292F.tmp; del 713A292F.tmp; "
            'put /tmp/live-note.txt "~$RG Eingang 2026.xlsx"; '
            'del "~$RG Eingang 2026.xlsx"'
        ),
        check_result=False,
    )
    check(
        transient_delete.returncode == 0,
        "temporary/document-lock deletion over SMB failed: "
        + (transient_delete.stderr.strip() or transient_delete.stdout.strip()),
    )
    transient_absent = engine_run(
        "exec",
        FILES_CONTAINER,
        "sh",
        "-ec",
        (
            "test ! -e '/data/groups/data/Finance/Reports/713A292F.tmp'; "
            "test ! -e '/data/groups/data/Finance/Reports/~$RG Eingang 2026.xlsx'; "
            "test -z \"$(find /data/groups/data/.trash -type f "
            "\\( -iname '*.tmp' -o -name '~$*' \\) -print -quit)\""
        ),
        check_result=False,
    )
    check(
        transient_absent.returncode == 0,
        "temporary or document-lock file was retained in the trash repository",
    )

    announce("real Samba recycle, admin download, and conflict-safe restore")
    trash_response = eventually(
        "deleted SMB file in the seven-day trash",
        lambda: http(
            query_path(
                "/api/trash",
                {"share": "Data", "path": "audit-moved.txt", "limit": "10"},
            ),
            token=token,
        ),
        lambda response: (
            response.status == 200
            and any(
                item.get("path") == "Finance/Reports/audit-moved.txt"
                for item in response.json().get("items", [])
            )
        ),
        timeout=30,
    )
    trash_items = trash_response.json().get("items", [])
    trash_item = next(
        item
        for item in trash_items
        if item.get("path") == "Finance/Reports/audit-moved.txt"
    )
    trash_download = http(
        query_path("/api/trash/download", {"id": str(trash_item["id"])}),
        token=token,
    )
    check(
        trash_download.status == 200
        and len(trash_download.body) == int(trash_item["size"])
        and "attachment" in trash_download.headers.get("Content-Disposition", ""),
        "trash download is missing, truncated, or not an attachment",
    )
    restored = http(
        "/api/trash/restore",
        method="POST",
        value={"id": trash_item["id"]},
        token=token,
    )
    check(
        restored.status == 200
        and restored.json().get("path") == "Finance/Reports/audit-moved.txt",
        f"trash restore failed: {restored.body!r}",
    )
    restored_read = engine_run(
        "exec",
        CLIENT_CONTAINER,
        "smbclient",
        f"//files.{DNS_DOMAIN}/Data",
        "-m",
        "SMB3",
        "-U",
        f"{WORKGROUP}\\alice%{USER_PASSWORD}",
        "-c",
        "cd Finance; cd Reports; get audit-moved.txt /tmp/restored-trash-file.txt",
        check_result=False,
    )
    check(restored_read.returncode == 0, "restored file is not readable over SMB")

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

    announce("high-level Samba audit ingestion, suffix exclusions, filters, facets, and pagination")
    required_actions = {"read", "write", "move", "delete"}
    activity = eventually(
        "all four live alice audit actions",
        lambda: http(query_path("/api/activity", {"user": "alice", "limit": "100"}), token=token),
        lambda response: (
            response.status == 200
            and required_actions.issubset(
                {event.get("action") for event in response.json().get("events", [])}
            )
        ),
        timeout=60,
    )
    activity_payload = activity.json()
    alice_actions = {event.get("action") for event in activity_payload["events"]}
    check(all("alice" in str(event.get("user", "")).casefold() for event in activity_payload["events"]), "activity user filter leaked unrelated events")
    check(alice_actions == required_actions, f"unexpected alice audit actions: {sorted(alice_actions)}")
    check(set(activity_payload.get("facets", {}).get("actions", [])) <= required_actions, "low-level activity category leaked into facets")
    check("Data" in activity_payload.get("facets", {}).get("shares", []), "activity share facets missing Data")

    moved = http(query_path("/api/activity", {"user": "alice", "action": "move", "limit": "100"}), token=token).json()
    check(moved.get("matched", 0) >= 1, "move action filter returned no event")
    check(all(event.get("action") == "move" for event in moved.get("events", [])), "move action filter leaked another action")

    eventually(
        "raw service-account SMB audit source",
        lambda: engine_run(
            "exec", FILES_CONTAINER, "grep", "-R", "report_svc", "/var/log/samba",
            check_result=False,
        ).returncode,
        lambda returncode: returncode == 0,
        timeout=30,
    )
    service_activity = http(query_path("/api/activity", {"user": "report_svc", "limit": "100"}), token=token).json()
    check(service_activity.get("matched") == 0, "_svc account was persisted in the activity archive")

    one_event = http(query_path("/api/activity", {"limit": "1"}), token=token).json()
    check(len(one_event.get("events", [])) == 1, "activity limit was ignored")
    check(one_event.get("nextCursor") is not None, "activity pagination cursor missing")

    announce("shared SQLite state, indexes, integrity, and ordered read deduplication")
    integrity = engine_run(
        "exec", FILES_CONTAINER, "sqlite3", "/state/shares.db", "PRAGMA quick_check;"
    )
    check(integrity.stdout.strip() == "ok", "shared SQLite database failed quick_check")
    tables = set(
        engine_run(
            "exec",
            FILES_CONTAINER,
            "sqlite3",
            "/state/shares.db",
            "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name;",
        ).stdout.splitlines()
    )
    check(
        {
            "shares",
            "audit_events",
            "audit_sources",
            "audit_daily_totals",
            "audit_daily_counts",
            "audit_daily_facets",
            "audit_rollup_state",
            "audit_paths",
            "audit_paths_fts",
            "audit_path_events",
            "web_cache",
        }.issubset(tables),
        f"shared SQLite tables are incomplete: {sorted(tables)}",
    )
    indexes = set(
        engine_run(
            "exec",
            FILES_CONTAINER,
            "sqlite3",
            "/state/shares.db",
            "SELECT name FROM sqlite_schema WHERE type='index' AND name LIKE 'audit_events_%';",
        ).stdout.splitlines()
    )
    check(
        {
            "audit_events_main_time",
            "audit_events_main_action_time",
            "audit_events_main_success_time",
            "audit_events_main_user_time",
            "audit_events_main_account_time",
            "audit_events_main_share_time",
            "audit_events_main_result_time",
            "audit_events_fslogix_time",
            "audit_events_fslogix_action_time",
            "audit_events_fslogix_success_time",
            "audit_events_fslogix_user_time",
            "audit_events_fslogix_account_time",
            "audit_events_fslogix_result_time",
        }.issubset(indexes),
        f"audit indexes are incomplete: {sorted(indexes)}",
    )
    duplicate_reads = engine_run(
        "exec",
        FILES_CONTAINER,
        "sqlite3",
        "/state/shares.db",
        """SELECT count(*) FROM (
            SELECT action, occurred_second, user, client_ip, share, path, success, result,
                   lag(action) OVER (ORDER BY id) AS previous_action,
                   lag(occurred_second) OVER (ORDER BY id) AS previous_second,
                   lag(user) OVER (ORDER BY id) AS previous_user,
                   lag(client_ip) OVER (ORDER BY id) AS previous_client_ip,
                   lag(share) OVER (ORDER BY id) AS previous_share,
                   lag(path) OVER (ORDER BY id) AS previous_path,
                   lag(success) OVER (ORDER BY id) AS previous_success,
                   lag(result) OVER (ORDER BY id) AS previous_result
            FROM audit_events
        ) WHERE action='read' AND previous_action='read'
          AND occurred_second=previous_second AND user=previous_user
          AND client_ip=previous_client_ip AND share=previous_share
          AND path=previous_path AND success=previous_success
          AND (success=1 OR result=previous_result);""",
    )
    check(duplicate_reads.stdout.strip() == "0", "uninterrupted duplicate reads remain")
    legacy_archive = engine_run(
        "exec", FILES_CONTAINER, "test", "!", "-e", "/state/audit", check_result=False
    )
    check(legacy_archive.returncode == 0, "legacy JSONL audit archive still exists")

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

    announce("encrypted non-solid per-group archives at the backup target")
    archive_check = engine_run(
        "exec",
        BACKUP_CONTAINER,
        "sh",
        "-ec",
        """
archive=$(find /backup/fileserver/snapshots -path '*/data/groups/data/Finance.7z' -type f | sort | tail -n 1)
test -n "$archive"
archive_dir=${archive%/*}
archive_count=$(find "$archive_dir" -maxdepth 1 -type f -name '*.7z' | wc -l | tr -d ' ')
test "$archive_count" -eq 3
test ! -d "$archive_dir/Finance"
listing=$(printf '%s\n' "$PREVIEW_ARCHIVE_PASSWORD" | 7z l -slt "$archive")
printf '%s\n' "$listing" | grep -q '^Solid = -$'
printf '%s\n' "$listing" | grep -q '^Encrypted = +$'
if printf '%s\n' 'wrong archive password' | 7z l -slt "$archive" >/dev/null 2>&1; then
    exit 1
fi
""",
        check_result=False,
    )
    check(
        archive_check.returncode == 0,
        "group archive is missing, solid, unencrypted, or accepted a wrong password: "
        + (archive_check.stderr.strip() or archive_check.stdout.strip()),
    )

    announce("authenticated manual backup action and terminal status")
    manual_backup_start = eventually(
        "manual backup action acceptance",
        lambda: http("/api/actions/backup", method="POST", value={}, token=token),
        lambda response: response.status == 202,
        timeout=30,
    )
    check(
        manual_backup_start.json().get("action") == "backup",
        "manual backup action returned the wrong payload",
    )
    manual_backup = eventually(
        "manual web backup completion",
        lambda: http("/api/backup", token=token),
        lambda response: (
            response.status == 200
            and response.json().get("trigger") == "web"
            and response.json().get("state") in {"completed", "failed"}
        ),
        timeout=240,
        interval=2,
    ).json()
    check(manual_backup.get("state") == "completed", f"manual web backup failed: {manual_backup}")
    check(float(manual_backup.get("percent", 0)) == 100.0, "manual web backup is not at 100%")

    announce("authenticated reconciliation action, progress status, and live log")
    reconciliation_start = eventually(
        "manual reconciliation action acceptance",
        lambda: http("/api/actions/reconciliation", method="POST", value={}, token=token),
        lambda response: response.status == 202,
        timeout=30,
    )
    check(
        reconciliation_start.json().get("action") == "reconciliation",
        "manual reconciliation action returned the wrong payload",
    )
    reconciliation = eventually(
        "manual reconciliation completion",
        lambda: http("/api/reconciliation", token=token),
        lambda response: (
            response.status == 200
            and response.json().get("trigger") == "web"
            and response.json().get("state") in {"completed", "failed"}
        ),
        timeout=240,
        interval=1,
    ).json()
    check(
        reconciliation.get("state") == "completed",
        f"manual reconciliation failed: {reconciliation}",
    )
    check(
        float(reconciliation.get("percent", 0)) == 100.0
        and reconciliation.get("phase") == "completed",
        "completed reconciliation status is incomplete",
    )
    check(
        any("completed" in line.casefold() for line in reconciliation.get("log", [])),
        "reconciliation completion is absent from the live log",
    )

    announce("overview and system health aggregation")
    overview = http("/api/overview", token=token)
    check(overview.status == 200 and overview.json().get("activeGroups") == 3, "overview group count is wrong")
    system = http("/api/system", token=token)
    check(system.status == 200, f"system endpoint failed: {system.body!r}")
    system_payload = system.json()
    check(system_payload.get("checks", {}).get("domainTrust") is True, "system reports broken AD trust")
    check(system_payload.get("checks", {}).get("sambaConfig") is True, "system reports invalid Samba config")
    check(system_payload.get("tls", {}).get("sans"), "system TLS summary is empty")
    check(system_payload.get("audit", {}).get("days", 0) >= 1, "system activity database summary is incomplete")

    announce("log-free PDF report snapshot")
    report = http("/api/report", token=token)
    check(report.status == 200, f"report endpoint failed: {report.body!r}")
    report_payload = report.json()
    check(
        set(report_payload) == {"generatedAt", "groups", "storage", "backup", "system"},
        f"report snapshot has unexpected sections: {sorted(report_payload)}",
    )
    check("log" not in report_payload["backup"], "backup log leaked into report snapshot")
    check("audit" not in report_payload["system"], "activity metadata leaked into report snapshot")
    check("usage" not in report_payload["system"], "duplicate usage leaked into report snapshot")
    check(
        report_payload["groups"].get("groups") == groups_payload.get("groups"),
        "report membership hierarchy differs from the group API",
    )
    report_totals = report_payload["storage"].get("totals", {})
    check(
        all(int(report_totals.get(field, 0)) > 0 for field in (
            "dataBytes",
            "privateBytes",
            "fslogixBytes",
        )),
        "report storage snapshot is incomplete",
    )
    check(
        report_payload["backup"].get("state") == backup_payload.get("state"),
        "report backup status differs from the backup API",
    )

    announce("individual AD-user folder assignments and all four SMB permission levels")
    check(http("/api/access").status == 401, "anonymous access-policy listing accepted")
    check(http("/api/access", method="POST", value={"action": "create-folder", "name": "Unauthorized"}).status == 401, "anonymous access-policy mutation accepted")
    access = http("/api/access", token=token).json()
    user_sids = {u["sam"]: u["sid"] for u in access["users"]}

    def change(value):
        response = eventually("access-policy update", lambda: http("/api/access", method="POST", value=value, token=token), lambda r: r.status != 409, timeout=45)
        check(response.status == 200, f"policy update failed: {response.body!r}")
        return response.json()

    created = change({"action": "create-folder", "name": "Permissions"})
    folder_id = next(f["id"] for f in created["folders"] if f["name"] == "Permissions")
    check("groups" not in access, "access API still advertises groups")
    rejected = http("/api/access", method="POST", value={"action": "save-group", "name": "Editors", "members": [user_sids["alice"]]}, token=token)
    check(rejected.status == 400, "group creation accepted")
    rejected = http("/api/access", method="POST", value={"action": "set-permissions", "id": folder_id,
                    "permissions": [{"kind": "group", "principalId": "legacy", "level": 3}]}, token=token)
    check(rejected.status == 400, "group folder assignment accepted")

    def rules(level):
        return change({"action": "set-permissions", "id": folder_id,
                       "permissions": [{"kind": "user", "principalId": user_sids["alice"], "level": level}]})

    def smb(command, user="alice"):
        result = engine_run("exec", CLIENT_CONTAINER, "smbclient", f"//files.{DNS_DOMAIN}/Data", "-m", "SMB3",
                            "-U", f"{WORKGROUP}\\{user}%{ADMIN_PASSWORD if user == ADMIN_USER else USER_PASSWORD}", "-c", command, check_result=False)
        return result.returncode, result.stdout + result.stderr

    # The SMB client sometimes exits zero on individual denied operations, so inspect status output.
    def allowed(command, user="alice"):
        code, output = smb(command, user)
        check(code == 0 and "NT_STATUS_" not in output, f"operation unexpectedly failed: {command}: {output}")

    def denied(command):
        code, output = smb(command)
        check(code != 0 or "NT_STATUS_ACCESS_DENIED" in output, f"operation unexpectedly succeeded: {command}: {output}")

    rules(0)
    denied("cd Permissions; ls")
    _, listing = smb("ls")
    check("Permissions" not in listing, "level 0 folder is visible")
    allowed("cd Permissions; put /tmp/live-note.txt existing.txt", ADMIN_USER)
    rules(1)
    allowed("cd Permissions; get existing.txt /tmp/permission-read.txt")
    denied("cd Permissions; put /tmp/live-note.txt blocked.txt")
    denied("cd Permissions; del existing.txt")
    rules(2)
    allowed("cd Permissions; put /tmp/live-note.txt created.txt")
    allowed("cd Permissions; put /tmp/live-note.txt existing.txt")
    allowed("cd Permissions; mkdir Child")
    allowed("cd Permissions; cd Child; put /tmp/live-note.txt inherited.txt")
    denied("cd Permissions; del existing.txt")
    denied("cd Permissions; del created.txt")
    denied("cd Permissions; rename created.txt renamed.txt")
    denied("cd Permissions; rmdir Child")
    denied("cd Permissions; cd Child; del inherited.txt")
    # Users must not promote themselves using SMB ACL changes, even on their own new files.
    acl_edit = engine_run("exec", CLIENT_CONTAINER, "smbcacls", f"//files.{DNS_DOMAIN}/Data", "Permissions/created.txt",
                          "-U", f"{WORKGROUP}\\alice%{USER_PASSWORD}", "--add", f"ACL:{WORKGROUP}\\alice:ALLOWED/0x0/FULL", check_result=False)
    check(acl_edit.returncode != 0, "level 2 user can change ACLs on a created file")
    rules(3)
    allowed("cd Permissions; rename created.txt renamed.txt")
    allowed("cd Permissions; del renamed.txt")
    allowed("cd Permissions; cd Child; del inherited.txt")
    allowed("cd Permissions; rmdir Child")
    # Assigning Bob does not grant Alice access; zero explicitly revokes Alice.
    change({"action": "set-permissions", "id": folder_id, "permissions": [
        {"kind": "user", "principalId": user_sids["bob"], "level": 3},
        {"kind": "user", "principalId": user_sids["alice"], "level": 0}]})
    denied("cd Permissions; ls")
    allowed("cd Permissions; ls", "bob")
    change({"action": "archive-folder", "id": folder_id})
    code, output = smb("cd Permissions; ls", "bob")
    check(code != 0 or "NT_STATUS_" in output, "archived folder remains accessible")
    change({"action": "restore-folder", "id": folder_id})
    allowed("cd Permissions; ls", "bob")
    change({"action": "set-permissions", "id": folder_id, "permissions": []})
    code, output = smb("cd Permissions; ls", "bob")
    check(code != 0 or "NT_STATUS_ACCESS_DENIED" in output, "removed individual assignment still grants access")
    invalid = http("/api/access", method="POST", value={"action": "create-folder", "name": "../escape"}, token=token)
    check(invalid.status == 400, "unsafe folder path accepted")

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
