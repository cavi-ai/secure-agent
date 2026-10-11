#!/usr/bin/env python3
"""Verify a tagged docs archive; upload only with an explicit --publish flag."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

import build


def verify_release(tag):
    identity, _ = build.identity(version=tag.removeprefix("v"), tag=tag)
    archive = build.ROOT / "dist" / f"secure-agent-docs-{tag}.tar.gz"
    sidecar = Path(str(archive) + ".sha256")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    expected = f"{checksum}  {archive.name}\n"
    if sidecar.read_text() != expected:
        raise ValueError("docs archive checksum mismatch")
    prefix = PurePosixPath(f"docs/secure-agent/{tag}")
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        with tarfile.open(archive) as source:
            seen = set()
            for member in source:
                path = PurePosixPath(member.name)
                if not member.isfile() or path.is_absolute() or ".." in path.parts or not (path.is_relative_to(prefix) or member.name == "cavi-release.json"):
                    raise ValueError(f"unsafe docs archive entry: {member.name}")
                relative = path.relative_to(prefix) if path.is_relative_to(prefix) else path
                if relative == PurePosixPath(".") or relative in seen:
                    raise ValueError("duplicate or empty docs archive entry")
                seen.add(relative)
                output = directory / "docs" / relative if member.name != "cavi-release.json" else directory / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as body:
                    output.write_bytes(body.read())
        manifest = build.verify(directory / "docs")
        if manifest["release"] != identity["release"] or manifest["version"] != identity["version"]:
            raise ValueError("docs archive does not match the checked-out product tag")
        if json.loads((directory / "cavi-release.json").read_text()) != build.release_metadata(manifest):
            raise ValueError("cavi-release.json does not match the verified docs provenance")
    envelope_path = archive.with_name(archive.name.removesuffix(".tar.gz") + ".release.json")
    if json.loads(envelope_path.read_text()) != build.release_envelope(manifest, archive.name, checksum):
        raise ValueError("release envelope does not match the verified archive")
    return [archive, sidecar, envelope_path]


def gh(*args, body=None, token=None):
    environment = {**os.environ, "GH_TOKEN": token} if token else None
    result = subprocess.run(["gh", *args], input=body, env=environment, text=True, capture_output=True)
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


def notify_cavi_home(envelope_path, token):
    envelope = json.loads(envelope_path.read_text())
    gh("api", "--method", "POST", "repos/cavi-ai/cavi-home/dispatches", "--input", "-",
       body=json.dumps({"event_type": "cavi-oss-release", "client_payload": envelope}), token=token)
    print("Requested cavi-home documentation ingestion")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", help="GitHub owner/repository; required for publication")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--notify-cavi-home", action="store_true",
                        help="after publication, dispatch to the registered host using CONSUMER_DISPATCH_TOKEN")
    args = parser.parse_args()
    if args.publish and args.repo != "cavi-ai/secure-agent":
        parser.error("--publish requires --repo cavi-ai/secure-agent")
    token = os.environ.get("CONSUMER_DISPATCH_TOKEN")
    if args.notify_cavi_home and (not args.publish or args.repo != "cavi-ai/secure-agent" or not token):
        parser.error("--notify-cavi-home requires --publish, --repo cavi-ai/secure-agent and CONSUMER_DISPATCH_TOKEN")
    assets = verify_release(args.tag)
    if args.publish:
        publish(args.tag, args.repo, assets)
        if args.notify_cavi_home:
            notify_cavi_home(assets[2], token)
    else:
        print("Verified tagged docs archive; no release assets uploaded")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
