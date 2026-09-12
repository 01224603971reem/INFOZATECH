#!/usr/bin/env python3
"""File Integrity Checker for authorized folders.

Creates a SHA-256 baseline and compares a folder against it later to detect
modified, added, or deleted files. The tool does not modify the scanned folder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

DEFAULT_ALGORITHM = "sha256"
DEFAULT_CHUNK_SIZE = 1024 * 1024


def hash_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        while chunk := file_handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def collect_hashes(folder: Path) -> Dict[str, str]:
    if not folder.exists():
        raise FileNotFoundError(f"Folder does not exist: {folder}")
    if not folder.is_dir():
        raise NotADirectoryError(f"Not a folder: {folder}")

    hashes: Dict[str, str] = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            relative_path = path.relative_to(folder).as_posix()
            hashes[relative_path] = hash_file(path)
    return hashes


def save_baseline(folder: Path, baseline_path: Path) -> None:
    hashes = collect_hashes(folder)
    payload = {
        "format": 1,
        "algorithm": DEFAULT_ALGORITHM,
        "root_folder": str(folder.resolve()),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": hashes,
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Baseline saved: {baseline_path}")
    print(f"Files recorded: {len(hashes)}")


def load_baseline(baseline_path: Path) -> dict:
    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Baseline does not exist: {baseline_path}") from exc
    if payload.get("algorithm") != DEFAULT_ALGORITHM or not isinstance(payload.get("files"), dict):
        raise ValueError("Unsupported or invalid baseline format")
    return payload


def compare(folder: Path, baseline_path: Path) -> int:
    baseline = load_baseline(baseline_path)
    previous = baseline["files"]
    current = collect_hashes(folder)

    previous_paths = set(previous)
    current_paths = set(current)
    added = sorted(current_paths - previous_paths)
    deleted = sorted(previous_paths - current_paths)
    modified = sorted(
        path for path in current_paths & previous_paths if current[path] != previous[path]
    )

    print(f"Compared folder: {folder.resolve()}")
    print(f"Baseline created: {baseline.get('created_at_utc', 'unknown')}")
    print(f"Added: {len(added)} | Modified: {len(modified)} | Deleted: {len(deleted)}")

    for label, paths in (("ADDED", added), ("MODIFIED", modified), ("DELETED", deleted)):
        for path in paths:
            print(f"{label}: {path}")

    if not (added or modified or deleted):
        print("STATUS: No changes detected.")
        return 0
    print("STATUS: Changes detected.")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect file changes using SHA-256 hashes.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser("baseline", help="Create a baseline snapshot.")
    baseline_parser.add_argument("folder", type=Path)
    baseline_parser.add_argument("--output", type=Path, default=Path("baseline.json"))

    compare_parser = subparsers.add_parser("compare", help="Compare a folder with a baseline.")
    compare_parser.add_argument("folder", type=Path)
    compare_parser.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "baseline":
            save_baseline(args.folder, args.output)
            return 0
        return compare(args.folder, args.baseline)
    except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
