"""Hardened ``docker run`` construction for the PIIAT-Mem Volatility image.

The image is stripped to Volatility 3 + the baked wrapper (uid 0 renamed and
locked, no shell, no package manager, runs as uid 2000). Every run is confined:
no capabilities, no new privileges, a read-only root filesystem, a pids limit,
and no network unless ISF symbol download is explicitly requested. Pure list
builders so the argv stays testable.

``run()`` additionally reads the group owning each read-only (evidence/renderer/
plugins) mount and ``--group-add``'s it, so a locked-down evidence tree and the
mounted renderer/plugins are readable by the image's non-root uid off defaults —
on a hardened host the memory image, the renderer and the plugins dir are
``root:docker`` with no world access, which uid 2000 cannot read otherwise
(``[Errno 13] Permission denied``). Read-write mounts (the symbol cache, made
world-writable by the caller) and the root group are skipped.
"""
from __future__ import annotations

import os

HARDENING_FLAGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "512",
    "--read-only",
]
_BASE_TMPFS = ["--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=1g"]


def run_flags(network: bool = False) -> list[str]:
    flags = list(HARDENING_FLAGS) + list(_BASE_TMPFS)
    if not network:
        flags += ["--network", "none"]
    return flags


def _mount_group_ids(mounts) -> list[str]:
    """Supplementary gids the container needs to READ its read-only mounts.

    Evidence, the renderer and the plugins dir are bind-mounted read-only and
    owned by whatever group staged them (``root:docker`` with no world access on
    a locked-down host). The image runs as the baked non-root uid 2000, which is
    not in that group, so it cannot read those mounts unless granted the gid.
    Return the distinct gid of each read-only mount's host source for
    ``--group-add``. Read-write mounts (the symbol cache the caller makes
    world-writable) are skipped, as are the root group and any source that can't
    be stat'd (keeps placeholder-path unit tests and absent mounts harmless)."""
    gids: list[str] = []
    for spec in mounts:
        parts = spec.split(":")
        if len(parts) < 3 or parts[-1] != "ro":
            continue
        try:
            gid = str(os.stat(parts[0]).st_gid)
        except OSError:
            continue
        if gid not in gids and gid != "0":
            gids.append(gid)
    return gids


def run(image: str, after_image=(), *, mounts=(), network: bool = False) -> list[str]:
    """``docker run`` argv. ``after_image`` is appended after the image name (the
    image's ENTRYPOINT is ``python3 /opt/dfir/vol_wrapper.py``, so these are the
    wrapper's arguments: the renderer path, then the Volatility CLI args).

    Each read-only mount's owning gid is ``--group-add``'d so the image's non-root
    uid can read locked-down evidence/renderer/plugins off the mount — no per-run
    --user/--group knobs threaded through."""
    argv = ["docker", "run", "--rm", *run_flags(network)]
    for gid in _mount_group_ids(mounts):
        argv += ["--group-add", gid]
    for mount in mounts:
        argv += ["-v", mount]
    argv += [image, *after_image]
    return argv
