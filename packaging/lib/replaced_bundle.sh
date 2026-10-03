#!/usr/bin/env bash
# Shared by packaging/install.sh and its test: where the installer moves the
# copy it replaces. Sourced, not executed.

# replaced_bundle_path <trash-dir> <app-name> <stamp>
# The Trash path for a replaced bundle, on stdout: "<app-name> <stamp>.app.replaced".
# No .app suffix, so LaunchServices does not list the trashed copy as a
# second registered app with the same bundle identifier.
replaced_bundle_path() {
  local trash_dir="$1" app_name="$2" stamp="$3"
  printf '%s/%s %s.app.replaced\n' "${trash_dir}" "${app_name}" "${stamp}"
}
