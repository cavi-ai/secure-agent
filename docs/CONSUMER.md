# Documentation artifacts

[Documentation](README.md) · [Development](DEVELOPMENT.md)

The Markdown in this repository is the documentation source. `docs/navigation.json` defines the reading order. Existing guide paths stay stable, and generated references are checked into `docs/reference/` so repository readers can use them without building anything.

## Build and check

Use Python 3.10+ and the Go version declared in `go.mod`:

```bash
make docs-reference  # regenerate CLI help, default YAML and API route policy
make docs-check      # require references to match source; validate navigation and examples
make docs-test       # verify artifact integrity, determinism and failure handling
make docs            # build a development artifact under dist/docs/secure-agent/
make docs-archive    # also write the archive and SHA-256 sidecar under dist/
```

The generator reads `secure-agent help`, the embedded default YAML and the canonical Go API route registry. It does not start the daemon, load personal configuration or contact an agent. Checks validate local Markdown links and heading anchors, navigation coverage, shell syntax, JSON examples and YAML syntax. Illustrative envelopes with an explicit ellipsis are excluded from JSON parsing. YAML parsing does not establish that every illustrated value is suitable for a particular deployment.

Generated route metadata is an access-policy inventory, not a full HTTP schema. Request and response details remain in [API](API.md). When behavior changes, update its guide and reference contract, run `make docs-reference`, and include the generated diff with the change. CI runs the checks, pipeline tests and a development archive build. Download `secure-agent-docs-preview-<commit>` from the CI run's Artifacts section to inspect its archive and checksum. Preview artifacts are retained for 14 days and advertise no stable public alias.

## Development and release identity

Development builds use `dev-<commit-prefix>` with a `-dirty` suffix when the checkout has changes. Their manifest identifies the source commit and dirty state. They advertise no public version path or stable alias. The repository guides describe current development behavior; published app downloads can lag behind it.

For release documentation, check out the actual product tag in a clean tree. Supply both the product version and its tag to the archive command. Replace `X.Y.Z` below with the version of the tag checked out at HEAD:

```bash
python3 packaging/docs/build.py archive --version X.Y.Z --release-tag vX.Y.Z
```

The command rejects a dirty tree, missing tag, mismatched tag or tag pointing at another commit. It does not infer a release version from CHANGELOG or publish anything. Do not build newer behavior under an older release label. Older tags that predate this tooling need their own release integration; running this command from current main does not recreate their docs.

## Artifact layout and host contract

A release archive is named `secure-agent-docs-v<version>.tar.gz`, with a sidecar of the same name plus `.sha256`. Its contents are rooted at `docs/secure-agent/v<version>/`:

```text
manifest.json
navigation.json
README.md
CONTRIBUTING.md
SECURITY.md
CHANGELOG.md
LICENSE
docs/                    # curated guides and generated reference pages
assets/                  # images referenced by the pages
```

Navigation uses `sections[]` with a `title` and `pages[]`, each containing `title` and `path`. Paths are relative to the artifact root. Every published Markdown page appears exactly once. Internal page and image links remain relative; repository-source links become GitHub links pinned to the source commit.

The manifest has `schemaVersion: 1`, `package` and `product` equal to `secure-agent`, `version`, `source.commit`, `source.dirty`, `release`, `generatedAt` and `contentSha256`. Release manifests have `release: {tag, commit}`, `publicBasePath: /docs/secure-agent/v<version>` and `stableAlias: /docs/secure-agent`. Development manifests use `release: null` and null public paths. These fields define the ingestion contract; they do not claim that a hosted site or release upload already exists.

`contentSha256` hashes each regular file except root `manifest.json`, sorted lexicographically by relative POSIX path: append the UTF-8 path, a NUL byte, the file bytes and a NUL byte for each file to one SHA-256 stream. The archive's sidecar hashes the compressed archive itself. A checksum detects corruption; authenticated release provenance must be checked independently.

Before ingestion, verify the archive sidecar, reject unsafe archive paths and links, extract to an isolated directory, and run:

```bash
python3 packaging/docs/build.py verify --directory EXTRACTED_ARTIFACT_ROOT
```

Match the version, tag and source commit against the intended GitHub release before accepting it. A host renders the supplied navigation and replaces the complete immutable version directory. Advance the stable alias only after all checks pass; do not invent missing pages or serve development artifacts at the stable alias.

Build timestamps default to the source commit's timestamp. `SOURCE_DATE_EPOCH` can supply the release build epoch. Archive file order, permissions, owner metadata and gzip timestamps are normalized. Rebuilding with the same inputs and epoch produces the same bytes. Existing archives and sidecars can be reused only when their bytes match; a different immutable artifact is refused.

## Release delivery

The [Publish product documentation workflow](../.github/workflows/publish-docs.yml) checks out the exact product tag, verifies its clean source identity, builds the archive and retains it as a workflow artifact. When a stable GitHub release is published, it attaches the archive and sidecar to that existing release. Prerelease events are excluded.

For a preview, run the workflow manually with an existing `vX.Y.Z` tag and leave **publish** off. This verifies the tagged archive without uploading release assets. To attach docs to an existing published stable release, enable **publish**. Older tags that lack this tooling are unsupported; the workflow does not use newer docs as a substitute for their source.

Release pipelines that create releases with `GITHUB_TOKEN` must call this reusable workflow explicitly, because those release events do not trigger another workflow. Supply `tag` and `publish: true`, with `contents: write` available to the called workflow. The docs workflow creates no tags or releases.

The publication helper rechecks the archive checksum, safe extraction, content digest and tag/commit identity before contacting GitHub. It refuses drafts, prereleases, differently named releases and remote tags that no longer resolve to the verified commit. Existing archive and sidecar bytes must match exactly; identical assets are reused, missing assets are uploaded, and differing assets are never overwritten. A failed download is an error, not permission to replace an asset.

Host ingestion and stable-alias promotion remain separate operations under the contract above; attaching release assets does not publish a hosted documentation site.
