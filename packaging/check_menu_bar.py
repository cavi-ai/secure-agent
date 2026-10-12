#!/usr/bin/env python3
"""Read-only check of Control Center's saved permission for an app's menu bar."""

import argparse
from pathlib import Path
import plistlib
import sys


def blocked_owners(preferences, bundle_id):
    """Include foreign owners: the app's own allowed record is not sufficient."""
    if not isinstance(preferences, dict):
        raise ValueError("Unsupported Control Center preferences format")
    encoded = preferences.get("trackedApplications")
    if not isinstance(encoded, bytes):
        raise ValueError("Control Center has no supported app tracking record")
    records = plistlib.loads(encoded)
    # Codable dictionaries with structured location keys encode as alternating
    # keys and values, inside a binary plist stored as NSData.
    if not isinstance(records, list) or len(records) % 2:
        raise ValueError("Unsupported Control Center app tracking format")
    target = {"bundle": {"_0": bundle_id}}
    blockers = []
    for location, record in zip(records[::2], records[1::2]):
        if not isinstance(location, dict) or not isinstance(record, dict):
            raise ValueError("Invalid Control Center app tracking record")
        members = record.get("menuItemLocations")
        allowed = record.get("isAllowed")
        if not isinstance(members, list) or not isinstance(allowed, bool):
            raise ValueError("Unsupported Control Center permission format")
        if not allowed and (location == target or target in members):
            blockers.append(location)
    return blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-id", default="com.cavi-ai.secure-agent")
    parser.add_argument(
        "--preferences", type=Path,
        default=Path.home() / "Library/Group Containers/group.com.apple.controlcenter"
        / "Library/Preferences/group.com.apple.controlcenter.plist",
    )
    args = parser.parse_args()
    try:
        blockers = blocked_owners(plistlib.loads(args.preferences.read_bytes()), args.bundle_id)
    except PermissionError:
        print("Full Disk Access is required to inspect Control Center's menu-bar record", file=sys.stderr)
        return 2
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        print(f"Cannot inspect menu-bar tracking: {error}", file=sys.stderr)
        return 2
    if blockers:
        print(f"Control Center blocks {args.bundle_id} through {blockers!r}", file=sys.stderr)
        return 1
    print(f"No disabled Control Center record blocks {args.bundle_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
