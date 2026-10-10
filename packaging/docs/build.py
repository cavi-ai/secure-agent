#!/usr/bin/env python3
"""Build and verify source-synchronized documentation with only Python and Go."""

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/reference"
FENCES = re.compile(r"^```([^\n]*)\n(.*?)^```\s*$", re.M | re.S)
LINKS = re.compile(r"(!?\[[^\]\n]*\]\()([^\n)]+)(\))|(<img\b[^>]*\bsrc=\")([^\"]+)(\")")
SEMVER = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def run(*args, input=None):
    result = subprocess.run(args, cwd=ROOT, input=input, text=True,
                            capture_output=True, env={**os.environ, "CGO_ENABLED": "0"})
    if result.returncode:
        raise ValueError(f"{' '.join(args)} failed:\n{result.stderr or result.stdout}")
    return result.stdout


def documents():
    return [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")] + sorted((ROOT / "docs").rglob("*.md"))


def anchors(text):
    text = FENCES.sub("", text)
    found = set(re.findall(r'<a\s+[^>]*id="([^"]+)"', text))
    counts = {}
    for label in re.findall(r"^#{1,6}\s+(.+)", text, re.M):
        label = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", label)
        slug = re.sub(r"[^\w\- ]", "", label.lower()).replace(" ", "-")
        n = counts.get(slug, 0)
        counts[slug] = n + 1
        found.add(slug if n == 0 else f"{slug}-{n}")
    return found


def destination(page, target, allow_generated=False):
    target = target.split(' "', 1)[0].strip("<>")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    dest = (page.parent / unquote(parsed.path)).resolve() if parsed.path else page
    if not dest.is_relative_to(ROOT):
        raise ValueError(f"{page.relative_to(ROOT)}: link escapes repository: {target}")
    if not dest.is_file():
        if allow_generated and dest in {REFERENCE / name for name in ("CLI.md", "DEFAULTS.md", "ROUTES.md")}:
            return dest
        raise ValueError(f"{page.relative_to(ROOT)}: missing link: {target}")
    if parsed.fragment and dest.suffix == ".md" and unquote(parsed.fragment) not in anchors(dest.read_text()):
        raise ValueError(f"{page.relative_to(ROOT)}: missing anchor: {target}")
    return dest


def navigation():
    nav = json.loads((ROOT / "docs/navigation.json").read_text())
    listed = []
    for section in nav["sections"]:
        if not section["title"] or not section["pages"]:
            raise ValueError("navigation sections need a title and pages")
        for page in section["pages"]:
            path = page["path"]
            if not page["title"] or path.startswith("/") or ".." in Path(path).parts:
                raise ValueError(f"invalid navigation entry: {page}")
            if not (ROOT / path).is_file() or not path.endswith(".md"):
                raise ValueError(f"missing navigation page: {path}")
            listed.append(path)
    expected = {str(p.relative_to(ROOT)) for p in documents()}
    if len(listed) != len(set(listed)) or set(listed) != expected:
        raise ValueError(f"navigation must list every page once; missing={sorted(expected - set(listed))}, extra={sorted(set(listed) - expected)}")
    return nav


def source_references(update=False):
    examples = []
    for page in documents():
        text = page.read_text()
        if len(re.findall(r"^```", text, re.M)) % 2:
            raise ValueError(f"{page.relative_to(ROOT)}: unbalanced fences")
        for match in LINKS.finditer(FENCES.sub("", text)):
            destination(page, match.group(2) or match.group(5), allow_generated=update)
        for language, body in FENCES.findall(text):
            language = language.strip()
            if language == "yaml":
                examples.append({"file": str(page.relative_to(ROOT)), "body": body})
            elif language in ("json", "jsonl"):
                # Some existing reference envelopes use an explicit ellipsis.
                if "..." not in body and "…" not in body:
                    try:
                        if language == "jsonl":
                            for line in body.splitlines():
                                if line.strip():
                                    json.loads(line)
                        else:
                            json.loads(body)
                    except ValueError as error:
                        raise ValueError(f"{page.relative_to(ROOT)}: invalid JSON: {error}") from error
            elif language in ("bash", "sh") and not re.search(r"(?<![\"'])<[a-zA-Z][^>]*>", body):
                run("bash", "-n", input=body)
    routes = json.loads(run("go", "run", "./daemon/cmd/docs-reference", input=json.dumps(examples)))
    help_text = run("go", "run", "./cmd/secure-agent", "help")
    banner = "<!-- Generated by make docs-reference. Do not edit by hand. -->\n\n"
    cli = banner + "# CLI command reference\n\n[Documentation](../README.md) · [CLI workflows](../USAGE.md#use-the-cli)\n\nGenerated from `secure-agent help` in this checkout. Help does not contact the daemon.\n\n```text\n" + help_text + "```\n"
    defaults = banner + "# Default configuration\n\n[Documentation](../README.md) · [Configuration guide](../CONFIGURATION.md)\n\nThe embedded `daemon/internal/config/defaults.yaml`, before path expansion or user overlays. Lists in user YAML replace default lists. Runtime overrides are described in the configuration guide.\n\n```yaml\n" + (ROOT / "daemon/internal/config/defaults.yaml").read_text() + "```\n"
    table = banner + "# API route registry\n\n[Documentation](../README.md) · [API contracts and authentication](../API.md)\n\nGenerated from `apiroutes.Table`, the same registry used by the daemon and console admission checks. This is a route and access-policy inventory, not an OpenAPI schema or a complete list of handler-supported methods. Consult the API guide for request and response contracts.\n\n**Console methods** lists methods admitted with the console credential. **UI mutations** require the pinned UI (or the owner when no UI is pinned) on the Unix socket. Owner-only routes exclude agents and the console; no-agent routes exclude agent processes; guard decisions use the separate decision policy. These classifications do not grant access by themselves.\n\n| Path | Console methods | UI mutations | Additional restriction | Response type |\n|---|---|---|---|---|\n"
    for route in routes:
        paths = [route["Path"]]
        if route["Prefix"] and route["Leaves"]:
            paths = [route["Path"] + "{id}/" + leaf["Path"] for leaf in route["Leaves"]]
        console = sorted(set(["GET", "HEAD"] + (route["MutatingMethods"] or []) + (route["ConsoleMethods"] or []))) if route["Console"] else []
        restriction = ", ".join(name for field, name in (("OwnerOnly", "owner only"), ("NoAgent", "no agents"), ("Decide", "guard decision")) if route[field]) or "—"
        for path in paths:
            response = route["Response"]
            if route["Prefix"] and route["Leaves"]:
                response = next(leaf["Response"] for leaf in route["Leaves"] if path.endswith("/" + leaf["Path"]))
            response_label = f"`{response}`" if response else "—"
            table += f"| `{path}` | {', '.join(console) or '—'} | {', '.join(route['MutatingMethods'] or []) or '—'} | {restriction} | {response_label} |\n"
    return {"CLI.md": cli, "DEFAULTS.md": defaults, "ROUTES.md": table}


def check_references(update=False):
    for name, content in source_references(update=update).items():
        path = REFERENCE / name
        if update:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        elif not path.exists() or path.read_text() != content:
            raise ValueError(f"stale generated reference: {path.relative_to(ROOT)}; run make docs-reference")


def digest(directory):
    hashed = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p != directory / "manifest.json"):
        hashed.update(path.relative_to(directory).as_posix().encode() + b"\0")
        hashed.update(path.read_bytes() + b"\0")
    return hashed.hexdigest()


def identity(version=None, tag=None):
    commit = run("git", "rev-parse", "HEAD").strip()
    dirty = bool(run("git", "status", "--porcelain", "--untracked-files=normal").strip())
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", run("git", "log", "-1", "--format=%ct").strip()))
    release = None
    if version or tag:
        if not version or not SEMVER.fullmatch(version) or tag != f"v{version}":
            raise ValueError("release builds require --version X.Y.Z and --release-tag vX.Y.Z")
        if dirty:
            raise ValueError("release documentation requires a clean checkout")
        if run("git", "rev-parse", f"refs/tags/{tag}^{{commit}}").strip() != commit:
            raise ValueError("release tag does not identify HEAD")
        release = {"tag": tag, "commit": commit}
    else:
        version = f"dev-{commit[:12]}" + ("-dirty" if dirty else "")
    return {"schemaVersion": 1, "package": "secure-agent", "product": "secure-agent",
            "version": version, "source": {"commit": commit, "dirty": dirty}, "release": release,
            "generatedAt": datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "publicBasePath": f"/docs/secure-agent/v{version}" if release else None,
            "stableAlias": "/docs/secure-agent" if release else None}, epoch


def artifact_path(path):
    relative = path.relative_to(ROOT).as_posix().lower().replace("_", "-")
    if not re.fullmatch(r"[a-z0-9./-]+", relative):
        raise ValueError(f"documentation artifact path must use portable ASCII: {relative}")
    return relative


def populate(directory, manifest, nav):
    pages = documents() + [ROOT / "LICENSE"]
    included = set(pages)
    if len({artifact_path(page) for page in pages}) != len(pages):
        raise ValueError("documentation artifact paths collide after normalization")
    assets = set()
    for page in pages:
        text = page.read_text()

        def rewrite(match):
            target = match.group(2) or match.group(5)
            dest = destination(page, target)
            fragment = urlsplit(target).fragment
            if dest and (dest in included or dest.is_relative_to(ROOT / "assets")):
                target = posixpath.relpath(artifact_path(dest), posixpath.dirname(artifact_path(page)) or ".")
                if fragment:
                    target += "#" + fragment
            if dest and dest not in included:
                if dest.is_relative_to(ROOT / "assets"):
                    assets.add(dest)
                else:
                    target = "https://github.com/cavi-ai/secure-agent/blob/" + manifest["source"]["commit"] + "/" + quote(dest.relative_to(ROOT).as_posix()) + ("#" + fragment if fragment else "")
            return (match.group(1) or match.group(4)) + target + (match.group(3) or match.group(6))

        # Fenced examples must retain literal Markdown/URLs.
        parts, cursor = [], 0
        for fence in FENCES.finditer(text):
            parts.extend([LINKS.sub(rewrite, text[cursor:fence.start()]), fence.group()])
            cursor = fence.end()
        parts.append(LINKS.sub(rewrite, text[cursor:]))
        output = directory / artifact_path(page)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("".join(parts))
    if len({artifact_path(path) for path in included | assets}) != len(included | assets):
        raise ValueError("documentation artifact paths collide after normalization")
    for asset in assets:
        dest = directory / artifact_path(asset)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(asset, dest)
    nav = {"title": "Secure Agent", "version": manifest["version"], "sections": [
        {"title": section["title"], "pages": [
            {**page, "path": artifact_path(ROOT / page["path"])} for page in section["pages"]
        ]} for section in nav["sections"]
    ]}
    (directory / "navigation.json").write_text(json.dumps(nav, indent=2) + "\n")
    manifest = {**manifest, "contentSha256": digest(directory)}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def verify(directory):
    directory = directory.resolve()
    if any(path.is_symlink() for path in directory.rglob("*")):
        raise ValueError("documentation artifacts cannot contain symbolic links")
    if any(not re.fullmatch(r"[a-z0-9./-]+", path.relative_to(directory).as_posix()) for path in directory.rglob("*") if path.is_file()):
        raise ValueError("documentation artifacts require lowercase portable paths")
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest.get("schemaVersion") != 1 or manifest.get("product") != "secure-agent" or manifest.get("package") != "secure-agent":
        raise ValueError("invalid documentation manifest identity")
    commit = manifest["source"]["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("invalid source commit")
    release = manifest["release"]
    if release:
        version = manifest["version"]
        if not SEMVER.fullmatch(version) or release != {"tag": f"v{version}", "commit": commit} or manifest["source"]["dirty"]:
            raise ValueError("invalid release provenance")
        if manifest["publicBasePath"] != f"/docs/secure-agent/v{version}" or manifest["stableAlias"] != "/docs/secure-agent":
            raise ValueError("invalid release paths")
    elif manifest["publicBasePath"] is not None or manifest["stableAlias"] is not None:
        raise ValueError("development docs cannot advertise release aliases")
    if digest(directory) != manifest["contentSha256"]:
        raise ValueError("documentation content digest mismatch")
    nav = json.loads((directory / "navigation.json").read_text())
    if nav.get("title") != "Secure Agent" or nav.get("version") != manifest["version"]:
        raise ValueError("artifact navigation identity does not match manifest")
    listed = []
    for section in nav["sections"]:
        if not section["title"] or not section["pages"]:
            raise ValueError("invalid artifact navigation section")
        for page in section["pages"]:
            if not page["title"]:
                raise ValueError("invalid artifact navigation title")
            target = directory / page["path"]
            if Path(page["path"]).is_absolute() or ".." in Path(page["path"]).parts or not target.resolve().is_relative_to(directory.resolve()) or not target.is_file():
                raise ValueError(f"missing or unsafe artifact page: {page['path']}")
            listed.append(page["path"])
    if len(listed) != len(set(listed)) or set(listed) != {p.relative_to(directory).as_posix() for p in directory.rglob("*.md")}:
        raise ValueError("artifact navigation must list every Markdown page once")
    for page in directory.rglob("*.md"):
        for match in LINKS.finditer(FENCES.sub("", page.read_text())):
            target = match.group(2) or match.group(5)
            parsed = urlsplit(target.split(' "', 1)[0].strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            dest = (page.parent / unquote(parsed.path)).resolve() if parsed.path else page
            if not dest.is_relative_to(directory.resolve()) or not dest.is_file():
                raise ValueError(f"broken artifact link: {page.relative_to(directory)}: {target}")
            if parsed.fragment and dest.suffix == ".md" and unquote(parsed.fragment) not in anchors(dest.read_text()):
                raise ValueError(f"broken artifact anchor: {target}")
    return manifest


def write_immutable(path, content):
    if path.exists() and path.read_bytes() != content:
        raise ValueError(f"refusing to replace different immutable artifact: {path}")
    path.write_bytes(content)


def release_metadata(manifest):
    if not manifest["release"]:
        raise ValueError("development docs have no release envelope")
    return {"schemaVersion": 1, "slug": "secure-agent", "kind": "product-docs",
            "version": manifest["version"], "tag": manifest["release"]["tag"],
            "repository": "cavi-ai/secure-agent", "commit": manifest["release"]["commit"]}


def release_envelope(manifest, archive_name, archive_sha256):
    metadata = release_metadata(manifest)
    return {**metadata, "artifact": {
        "url": f"https://github.com/{metadata['repository']}/releases/download/{metadata['tag']}/{archive_name}",
        "sha256": archive_sha256, "format": "tar.gz"}}


def archive(directory, manifest, epoch):
    prefix = f"docs/secure-agent/v{manifest['version']}"
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            entries = {prefix + "/" + path.relative_to(directory).as_posix(): path.read_bytes()
                       for path in directory.rglob("*") if path.is_file()}
            if manifest["release"]:
                entries["cavi-release.json"] = (json.dumps(release_metadata(manifest), indent=2) + "\n").encode()
            for name, body in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(body), epoch, 0o644
                tar.addfile(info, io.BytesIO(body))
    payload = stream.getvalue()
    path = ROOT / "dist" / f"secure-agent-docs-v{manifest['version']}.tar.gz"
    write_immutable(path, payload)
    write_immutable(Path(str(path) + ".sha256"), (hashlib.sha256(payload).hexdigest() + "  " + path.name + "\n").encode())
    if manifest["release"]:
        envelope = release_envelope(manifest, path.name, hashlib.sha256(payload).hexdigest())
        write_immutable(path.with_name(path.name.removesuffix(".tar.gz") + ".release.json"), (json.dumps(envelope, indent=2) + "\n").encode())
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("reference", "check", "build", "archive", "verify"))
    parser.add_argument("--version")
    parser.add_argument("--release-tag")
    parser.add_argument("--directory", type=Path, help="existing artifact to verify")
    args = parser.parse_args()
    if args.command == "verify":
        if not args.directory:
            parser.error("verify requires --directory")
        verify(args.directory)
        print(f"Verified {args.directory}")
        return
    check_references(update=args.command == "reference")
    if args.command == "reference":
        print("Updated CLI, defaults and route references")
        return
    nav = navigation()
    if args.command == "check":
        print(f"Checked {len(documents())} pages, navigation, links, anchors, examples and generated references")
        return
    manifest, epoch = identity(args.version, args.release_tag)
    parent = ROOT / "dist/docs/secure-agent"
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / f"v{manifest['version']}"
    with tempfile.TemporaryDirectory(dir=parent) as temp:
        staging = Path(temp)
        populate(staging, manifest, nav)
        verify(staging)
        if args.command == "archive":
            print(archive(staging, manifest, epoch))
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(staging, output)
    print(f"Built {output}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(str(error)) from error
