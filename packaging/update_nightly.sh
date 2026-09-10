#!/usr/bin/env bash
# update_nightly.sh — the nightly channel of the in-app updater.
# Builds and launches Secure Agent from the CURRENT origin/main of this
# checkout. Developer-grade channel: it requires a git checkout (stable
# releases need none) and builds in place with the repo's own toolchain.
#
# Invoked by the menubar's UpdateManager; also runnable by hand.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "==> Fetching origin/main..."
git fetch origin main

if ! git merge-base --is-ancestor HEAD origin/main 2>/dev/null; then
    echo "nightly: local checkout has commits not on origin/main (or is detached)." >&2
    echo "nightly: refusing to move your tree — update it yourself, then run make install." >&2
    exit 1
fi

echo "==> Fast-forwarding to origin/main..."
git merge --ff-only origin/main

echo "==> Building and launching..."
make install
