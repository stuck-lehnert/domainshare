#!/usr/bin/env python3
"""Safe listing, expiry, download, and restoration for Samba recycle bins."""

import argparse
import base64
import datetime as dt
import os
import re
import stat
from typing import BinaryIO, Dict, List, Optional, Tuple


TRASH_DIRECTORY = ".trash"
DEFAULT_RETENTION_DAYS = 7
VERSION_PREFIX_RE = re.compile(r"^Copy #\d+ of ", re.IGNORECASE)


def retention_days() -> int:
    try:
        value = int(os.getenv("TRASH_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
    except ValueError:
        value = DEFAULT_RETENTION_DAYS
    return max(1, min(365, value))


def share_roots() -> Dict[str, str]:
    return {
        "Data": os.path.abspath(os.getenv("GROUP_ROOT", "/data/groups/data")),
        "Private": os.path.abspath(os.getenv("PRIVATE_ROOT", "/data/private")),
        "FSLogix": os.path.abspath(os.getenv("FSLOGIX_ROOT", "/data/fslogix")),
    }


def trash_root(share_root: str) -> str:
    return os.path.join(share_root, TRASH_DIRECTORY)


def ensure_trash_roots() -> None:
    """Create non-listable sticky repositories users can write through Samba."""
    for root in share_roots().values():
        os.makedirs(root, exist_ok=True)
        repository = trash_root(root)
        os.makedirs(repository, exist_ok=True)
        try:
            os.chown(repository, 0, 0)
        except PermissionError:
            if os.geteuid() == 0:
                raise
        os.chmod(repository, 0o1733)


def _share_name(value: str) -> str:
    for name in share_roots():
        if name.casefold() == value.casefold():
            return name
    raise ValueError("Unbekannte Freigabe")


def _relative_parts(value: str) -> List[str]:
    if not value or value.startswith(("/", "\\")) or "\0" in value:
        raise ValueError("Ungültiger Papierkorbpfad")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Ungültiger Papierkorbpfad")
    return parts


def encode_item_id(share: str, relative_path: str) -> str:
    canonical_share = _share_name(share)
    _relative_parts(relative_path)
    payload = f"{canonical_share}\0{relative_path}".encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_item_id(item_id: str) -> Tuple[str, str]:
    if not item_id or len(item_id) > 8192:
        raise ValueError("Ungültige Papierkorb-ID")
    try:
        padding = "=" * (-len(item_id) % 4)
        payload = base64.b64decode(
            item_id + padding,
            altchars=b"-_",
            validate=True,
        ).decode("utf-8")
        share, relative_path = payload.split("\0", 1)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Ungültige Papierkorb-ID") from exc
    canonical_share = _share_name(share)
    _relative_parts(relative_path)
    return canonical_share, relative_path


def _original_relative(relative_path: str) -> str:
    parts = _relative_parts(relative_path)
    if len(parts) < 2:
        raise ValueError("Papierkorbeintrag enthält keinen Originalpfad")
    original = parts[1:]
    original[-1] = VERSION_PREFIX_RE.sub("", original[-1], count=1)
    if not original[-1]:
        raise ValueError("Papierkorbeintrag enthält keinen Dateinamen")
    return "/".join(original)


def _open_directory_chain(
    root: str,
    parts: List[str],
    *,
    create: bool = False,
    uid: int = 0,
    gid: int = 0,
    mode: int = 0o700,
) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open(root, flags)
    try:
        for part in parts:
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=mode, dir_fd=current_fd)
                os.chown(
                    part,
                    uid,
                    gid,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
                os.chmod(
                    part,
                    mode,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
                next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _resolved_item(item_id: str) -> Tuple[str, str, str, List[str], os.stat_result]:
    share, relative_path = decode_item_id(item_id)
    share_root = share_roots()[share]
    repository = trash_root(share_root)
    parts = _relative_parts(relative_path)
    parent_fd = _open_directory_chain(repository, parts[:-1])
    try:
        info = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Nur reguläre Dateien können verarbeitet werden")
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - retention_days() * 86400
    if info.st_mtime < cutoff:
        raise FileNotFoundError("Papierkorbeintrag ist abgelaufen")
    return share, share_root, relative_path, parts, info


def _iso_timestamp(seconds: float) -> str:
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat(
        timespec="seconds"
    )


def _item_payload(
    share: str,
    relative_path: str,
    info: os.stat_result,
    days: int,
) -> Dict[str, object]:
    original = _original_relative(relative_path)
    deleted_at = float(info.st_mtime)
    return {
        "id": encode_item_id(share, relative_path),
        "share": share,
        "path": original,
        "name": original.rsplit("/", 1)[-1],
        "deletedBy": relative_path.split("/", 1)[0],
        "deletedAt": _iso_timestamp(deleted_at),
        "expiresAt": _iso_timestamp(deleted_at + days * 86400),
        "size": int(info.st_size),
    }


def list_items(
    *,
    share: str = "",
    path: str = "",
    limit: int = 200,
    now: Optional[dt.datetime] = None,
) -> Dict[str, object]:
    days = retention_days()
    current = now or dt.datetime.now(dt.timezone.utc)
    cutoff = current.timestamp() - days * 86400
    selected_share = _share_name(share) if share else ""
    path_filter = path.strip().casefold()
    items: List[Dict[str, object]] = []

    for share_name, root in share_roots().items():
        if selected_share and share_name != selected_share:
            continue
        repository = trash_root(root)
        try:
            walker = os.walk(repository, topdown=True, followlinks=False)
            for directory, subdirectories, filenames in walker:
                safe_subdirectories = []
                for name in subdirectories:
                    candidate = os.path.join(directory, name)
                    try:
                        if not stat.S_ISLNK(os.lstat(candidate).st_mode):
                            safe_subdirectories.append(name)
                    except OSError:
                        continue
                subdirectories[:] = safe_subdirectories
                for filename in filenames:
                    candidate = os.path.join(directory, filename)
                    try:
                        info = os.lstat(candidate)
                    except OSError:
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_mtime < cutoff:
                        continue
                    relative_path = os.path.relpath(candidate, repository).replace(
                        os.sep, "/"
                    )
                    try:
                        payload = _item_payload(
                            share_name, relative_path, info, days
                        )
                    except ValueError:
                        continue
                    if path_filter and path_filter not in str(payload["path"]).casefold():
                        continue
                    items.append(payload)
        except OSError:
            continue

    items.sort(
        key=lambda item: (str(item["deletedAt"]), str(item["id"])),
        reverse=True,
    )
    maximum = max(1, min(500, int(limit)))
    return {
        "items": items[:maximum],
        "matched": len(items),
        "truncated": len(items) > maximum,
        "retentionDays": days,
        "scannedAt": current.isoformat(timespec="seconds"),
    }


def open_download(item_id: str) -> Tuple[BinaryIO, Dict[str, object]]:
    share, _share_root, relative_path, parts, _info = _resolved_item(item_id)
    repository = trash_root(share_roots()[share])
    parent_fd = _open_directory_chain(repository, parts[:-1])
    try:
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Nur reguläre Dateien können heruntergeladen werden")
        payload = _item_payload(share, relative_path, info, retention_days())
        return os.fdopen(file_fd, "rb"), payload
    except Exception:
        os.close(file_fd)
        raise


def _restore_directory_mode(share: str) -> int:
    if share == "Data":
        return 0o2770
    return 0o700


def _remove_empty_trash_parents(repository: str, relative_path: str) -> None:
    current = os.path.dirname(os.path.join(repository, relative_path))
    repository = os.path.abspath(repository)
    while (
        os.path.commonpath((repository, current)) == repository
        and current != repository
    ):
        try:
            os.rmdir(current)
        except OSError:
            break
        current = os.path.dirname(current)


def restore_item(item_id: str) -> Dict[str, object]:
    share, share_root, relative_path, parts, info = _resolved_item(item_id)
    original = _original_relative(relative_path)
    original_parts = _relative_parts(original)
    if original_parts[0] == TRASH_DIRECTORY:
        raise ValueError("Ungültiger Wiederherstellungspfad")

    source_parent_fd = _open_directory_chain(
        trash_root(share_root), parts[:-1]
    )
    destination_parent_fd = _open_directory_chain(
        share_root,
        original_parts[:-1],
        create=True,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=_restore_directory_mode(share),
    )
    linked = False
    try:
        os.link(
            parts[-1],
            original_parts[-1],
            src_dir_fd=source_parent_fd,
            dst_dir_fd=destination_parent_fd,
            follow_symlinks=False,
        )
        linked = True
        linked_info = os.stat(
            original_parts[-1],
            dir_fd=destination_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(linked_info.st_mode)
            or linked_info.st_dev != info.st_dev
            or linked_info.st_ino != info.st_ino
        ):
            os.unlink(original_parts[-1], dir_fd=destination_parent_fd)
            linked = False
            raise RuntimeError("Papierkorbeintrag wurde währenddessen verändert")
        try:
            os.unlink(parts[-1], dir_fd=source_parent_fd)
        except Exception:
            os.unlink(original_parts[-1], dir_fd=destination_parent_fd)
            linked = False
            raise
    finally:
        os.close(source_parent_fd)
        os.close(destination_parent_fd)

    if not linked:
        raise RuntimeError("Wiederherstellung konnte nicht abgeschlossen werden")
    _remove_empty_trash_parents(trash_root(share_root), relative_path)
    return {
        "restored": True,
        "share": share,
        "path": original,
    }


def cleanup_expired(now: Optional[dt.datetime] = None) -> Dict[str, int]:
    days = retention_days()
    current = now or dt.datetime.now(dt.timezone.utc)
    cutoff = current.timestamp() - days * 86400
    removed = 0
    removed_bytes = 0

    ensure_trash_roots()
    for root in share_roots().values():
        repository = trash_root(root)
        for directory, subdirectories, filenames in os.walk(
            repository, topdown=False, followlinks=False
        ):
            for filename in filenames:
                candidate = os.path.join(directory, filename)
                try:
                    info = os.lstat(candidate)
                    if info.st_mtime >= cutoff:
                        continue
                    if not (
                        stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    ):
                        continue
                    os.unlink(candidate)
                    removed += 1
                    if stat.S_ISREG(info.st_mode):
                        removed_bytes += int(info.st_size)
                except OSError:
                    continue
            for name in subdirectories:
                candidate = os.path.join(directory, name)
                try:
                    info = os.lstat(candidate)
                    if stat.S_ISLNK(info.st_mode):
                        if info.st_mtime < cutoff:
                            os.unlink(candidate)
                            removed += 1
                        continue
                    os.rmdir(candidate)
                except OSError:
                    continue
    return {"removed": removed, "removedBytes": removed_bytes}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    if not args.cleanup:
        parser.error("--cleanup is required")
    result = cleanup_expired()
    print(
        f"[trash] Removed {result['removed']} expired item(s) "
        f"({result['removedBytes']} bytes)",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
