"""Prepare signing entitlements from explicitly supplied local profiles."""
from datetime import datetime, timezone
from pathlib import Path
import plistlib
import subprocess
import sys

RESOURCES = Path(__file__).resolve().parents[2] / "model-filter" / "Resources"
CAPABILITY = "com.apple.developer.networking.networkextension"
APP_ID = "com.apple.application-identifier"
TEAM_ID = "com.apple.developer.team-identifier"


def entitlements(profile, template, team, bundle):
    values = profile.get("Entitlements", {})
    app_id = values.get(APP_ID)
    prefixes = profile.get("ApplicationIdentifierPrefix", [])
    if (profile.get("TeamIdentifier") != [team] or values.get(TEAM_ID) != team
            or not any(app_id == prefix + "." + bundle for prefix in prefixes)):
        raise ValueError("profile does not authorize the selected team and bundle ID")
    expires = profile.get("ExpirationDate")
    if not isinstance(expires, datetime) or expires.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise ValueError("profile is expired or has no expiration date")
    if not set(template[CAPABILITY]).issubset(values.get(CAPABILITY, [])):
        raise ValueError("profile does not authorize content filtering")
    return {**template, APP_ID: app_id, TEAM_ID: team}


def main():
    team, app_profile, extension_profile, destination = sys.argv[1:]
    for kind, profile_path, bundle in (
        ("host", app_profile, "com.cavi-ai.secure-agent"),
        ("provider", extension_profile, "com.cavi-ai.secure-agent.model-filter"),
    ):
        # CMS decoding reads only the owner-supplied file; it does not access an account.
        result = subprocess.run(["security", "cms", "-D", "-i", profile_path],
                                capture_output=True, check=True, timeout=10)
        profile = plistlib.loads(result.stdout)
        template = plistlib.loads((RESOURCES / (kind + ".entitlements")).read_bytes())
        prepared = entitlements(profile, template, team, bundle)
        (Path(destination) / (kind + ".entitlements")).write_bytes(plistlib.dumps(prepared))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        sys.exit("error: invalid model filter provisioning inputs: " + str(error))
