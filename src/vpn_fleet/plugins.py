"""Prepare only two official, checksum-pinned plugins; never execute downloaded code."""
import hashlib
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import urllib.request
import zipfile

PLUGIN_IDS = ("loki", "prometheus")


def validate_plugins(plugins):
    if not isinstance(plugins, dict) or set(plugins) != set(PLUGIN_IDS):
        raise ValueError("Exactly the official Loki and Prometheus plugins must be pinned")
    for plugin_id, value in plugins.items():
        if not isinstance(value, dict) or set(value) != {"version", "sha256", "url"}:
            raise ValueError("Incomplete official plugin lock")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]) or not re.fullmatch(r"[a-f0-9]{64}", value["sha256"]):
            raise ValueError("Plugins require exact stable versions and SHA256")
        if value["url"] != f"https://grafana.com/api/plugins/{plugin_id}/versions/{value['version']}/download?os=linux&arch=amd64":
            raise ValueError("Only the pinned official linux/amd64 plugin endpoint is allowed")


def plugin_hash(plugins):
    validate_plugins(plugins)
    return hashlib.sha256(json.dumps(plugins, sort_keys=True).encode()).hexdigest()


def plugin_artifact(plugin_id, lock):
    return f"grafana-plugin:{plugin_id}@sha256:{lock['sha256']}"


def fetch_archive(lock, target):
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == lock["sha256"]:
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=target.name + "-", suffix=".download", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        digest = hashlib.sha256(); size = 0
        request = urllib.request.Request(lock["url"], headers={"User-Agent": "private-vpn-fleet"})
        with os.fdopen(descriptor, "wb") as out, urllib.request.urlopen(request, timeout=120) as response:
            if not response.geturl().startswith("https://"):
                raise ValueError("Insecure plugin download redirect")
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > 128 * 1024 * 1024: raise ValueError("Plugin archive exceeds download limit")
                digest.update(block); out.write(block)
        if digest.hexdigest() != lock["sha256"]:
            raise ValueError("Official plugin archive checksum mismatch")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def unpack(archive, destination, plugin_id, version):
    """Reject traversal, links, duplicates, special files and oversized archives."""
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if len(entries) > 30000 or sum(i.file_size for i in entries) > 512 * 1024 * 1024:
            raise ValueError("Plugin extraction limit exceeded")
        seen = set()
        for info in entries:
            name = info.filename.rstrip("/")
            path = PurePosixPath(name)
            kind = stat.S_IFMT(info.external_attr >> 16)
            if (not name or path.is_absolute() or "\\" in name or ":" in name
                    or any(p in ("", ".", "..") for p in name.split("/"))
                    or path.parts[0] != plugin_id or name in seen
                    or kind not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError("Unsafe plugin archive member")
            seen.add(name)
            target = destination.joinpath(*path.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True); target.chmod(0o755)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(info) as incoming, target.open("xb") as out:
                    shutil.copyfileobj(incoming, out)
                target.chmod(0o755 if (info.external_attr >> 16) & 0o111 else 0o644)
    metadata = json.loads((destination / plugin_id / "plugin.json").read_text())
    if metadata["id"] != plugin_id or metadata["info"]["version"] != version:
        raise ValueError("Plugin archive identity/version differs from its lock")
    if not (destination / plugin_id / "MANIFEST.txt").is_file():
        raise ValueError("Signed plugin manifest is missing; unsigned loading is forbidden")


def tree_hash(path):
    files = {}
    for item in path.rglob("*"):
        if item.is_symlink(): raise ValueError("Symlink in prepared plugin tree")
        if item.is_file():
            files[item.relative_to(path).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
    return files


def prepare_plugins(plugins, root):
    identity = plugin_hash(plugins)
    archives, sets = root / "archives", root / "sets"
    archives.mkdir(parents=True, exist_ok=True); sets.mkdir(parents=True, exist_ok=True)
    destination = sets / identity
    with tempfile.TemporaryDirectory(prefix="prepare-", dir=sets) as temp:
        staging = Path(temp)
        for plugin_id, lock in plugins.items():
            archive = archives / (plugin_id + "-" + lock["sha256"] + ".zip")
            fetch_archive(lock, archive)
            unpack(archive, staging, plugin_id, lock["version"])
        # Public signed code is mounted into Grafana under a different UID. Its parent
        # .state remains private; the mounted set itself must be readable/traversable.
        staging.chmod(0o755)
        if destination.is_symlink():
            raise ValueError("Prepared plugin root must not be a symlink")
        if destination.exists():
            if tree_hash(destination) != tree_hash(staging):
                raise ValueError("Prepared plugin files have changed; refusing unreviewed content")
        else:
            try:
                os.rename(staging, destination)
            except OSError as exc:
                if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY) or destination.is_symlink():
                    raise
                if tree_hash(destination) != tree_hash(staging):
                    raise ValueError("Concurrent plugin preparation produced different files") from None
        destination.chmod(0o755)
    return destination
