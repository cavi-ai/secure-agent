#!/usr/bin/env python3
"""Check release bundle metadata against the selected source."""
import plistlib
import re
import sys


def main(path, tag, sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("expected a full source revision")
    with open(path, "rb") as stream:
        info = plistlib.load(stream)
    if info.get("CFBundleShortVersionString") != tag.removeprefix("v"):
        raise ValueError("app version does not match release tag")
    if info.get("SecureAgentSourceRevision") != sha:
        raise ValueError("app source revision does not match release source")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (ValueError, OSError, plistlib.InvalidFileException, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
