#!/usr/bin/env bash
# Print the commit selected by a release event or manual dispatch.
set -euo pipefail
tag="${INPUT_TAG:-${EVENT_TAG:-}}"
expected="${EXPECTED_SHA:-}"
if [[ -n "$expected" && -z "${INPUT_TAG:-}" ]]; then
  echo 'Expected SHA requires a manual release tag' >&2; exit 1
fi
sha="${GITHUB_SHA:?}"
if [[ -n "$tag" ]]; then
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
  sha="$(git rev-parse --verify "refs/tags/${tag}^{commit}")"
fi
if [[ -n "${INPUT_TAG:-}" ]]; then
  [[ "$expected" =~ ^[0-9a-f]{40}$ && "$sha" == "$expected" ]] || {
    echo 'Expected SHA must be the full commit resolved by the tag' >&2; exit 1;
  }
elif [[ -n "${EVENT_TAG:-}" && "$sha" != "$GITHUB_SHA" ]]; then
  echo 'Release tag no longer resolves to the event commit' >&2; exit 1
fi
printf '%s\n' "$sha"
