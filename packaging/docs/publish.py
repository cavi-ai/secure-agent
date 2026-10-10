#!/usr/bin/env python3
"""Verify a tagged docs archive; upload only with an explicit --publish flag."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

import build


def verify_release(tag):
    identity, _ = build.identity(version=tag.removeprefix("v"), tag=tag)
    archive = build.ROOT / "dist" / f"secure-agent-docs-{tag}.tar.gz"
    sidecar = Path(str(archive) + ".sha256")
    expected = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
    if sidecar.read_text() != expected:
        raise ValueError("docs archive checksum mismatch")
    prefix = PurePosixPath(f"docs/secure-agent/{tag}")
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        with tarfile.open(archive) as source:
            seen = set()
            for member in source:
                path = PurePosixPath(member.name)
                if not member.isfile() or path.is_absolute() or ".." in path.parts or not path.is_relative_to(prefix):
                    raise ValueError(f"unsafe docs archive entry: {member.name}")
                relative = path.relative_to(prefix)
                if relative == PurePosixPath(".") or relative in seen:
                    raise ValueError("duplicate or empty docs archive entry")
                seen.add(relative)
                output = directory / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as body:
                    output.write_bytes(body.read())
        manifest = build.verify(directory)
        if manifest["release"] != identity["release"] or manifest["version"] != identity["version"]:
            raise ValueError("docs archive does not match the checked-out product tag")
    return [archive, sidecar]


def gh(*args):
    result = subprocess.run(["gh", *args], text=True, capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "GitHub release operation failed")
    return result.stdout


def publish(tag, repository, assets):
    release = json.loads(gh("release", "view", tag, "--repo", repository,
                            "--json", "tagName,isDraft,isPrerelease,assets"))
    if release["tagName"] != tag or release["isDraft"] or release["isPrerelease"]:
        raise ValueError("docs uploads require an existing published stable release")
    remote_commit = gh("api", f"repos/{repository}/commits/{tag}", "--jq", ".sha").strip()
    if remote_commit != build.run("git", "rev-parse", "HEAD").strip():
        raise ValueError("remote product tag no longer matches the verified docs commit")
    names = {asset["name"] for asset in release["assets"]}
    pending = []
    # Compare every existing asset before uploading any missing asset. Never
    # overwrite a versioned archive, including on a workflow rerun.
    with tempfile.TemporaryDirectory() as temp:
        for asset in assets:
            if asset.name not in names:
                pending.append(str(asset))
                continue
            target = Path(temp) / asset.name
            gh("release", "download", tag, "--repo", repository,
               "--pattern", asset.name, "--output", str(target))
            if target.read_bytes() != asset.read_bytes():
                raise ValueError(f"existing release asset differs; refusing overwrite: {asset.name}")
    if pending:
        gh("release", "upload", tag, *pending, "--repo", repository)
    print("Release documentation assets match the verified archive")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", help="GitHub owner/repository; required for publication")
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    if args.publish and not args.repo:
        parser.error("--publish requires --repo")
    assets = verify_release(args.tag)
    if args.publish:
        publish(args.tag, args.repo, assets)
    else:
        print("Verified tagged docs archive; no release assets uploaded")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
