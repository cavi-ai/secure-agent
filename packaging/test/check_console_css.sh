#!/bin/bash
# check_console_css.sh — fail if the console stylesheet uses a CSS custom
# property that is never defined, or defines a @keyframes name twice.
# Regression guard: an undefined var(--x) renders as an invisible control
# (the critical posture dot once shipped that way), and a duplicate
# @keyframes silently overrides the earlier animation.
set -eu

css="$(dirname "$0")/../../daemon/internal/api/web_dist/style.css"

used=$(grep -oE 'var\(--[a-zA-Z0-9-]+' "$css" | sed 's/var(//' | sort -u)
defined=$(grep -oE '^[[:space:]]*--[a-zA-Z0-9-]+:' "$css" | tr -d ' :' | sort -u)

missing=$(comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$defined"))
if [ -n "$missing" ]; then
    echo "style.css: custom properties used but never defined:" >&2
    printf '  %s\n' $missing >&2
    exit 1
fi

dupes=$(grep -oE '^@keyframes [a-zA-Z0-9-]+' "$css" | awk '{print $2}' | sort | uniq -d)
if [ -n "$dupes" ]; then
    echo "style.css: duplicate @keyframes (later definition silently wins):" >&2
    printf '  %s\n' $dupes >&2
    exit 1
fi

echo "console css: all custom properties defined, no duplicate keyframes"
