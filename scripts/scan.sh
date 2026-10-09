#!/usr/bin/env bash
# Fail if anything personal or secret-looking is left in the tracked tree.
set -uo pipefail
cd "$(dirname "$0")/.."
pat='(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[bp]-|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|Bearer [A-Za-z0-9._-]{20,}|192\.168\.|10\.[0-9]+\.[0-9]+\.[0-9]+|@gmail\.com|/Users/[a-z]'
extra="${SCAN_EXTRA:-}"; [ -n "$extra" ] && pat="$pat|$extra"
if grep -rInE "$pat" --exclude-dir=.git --exclude=scan.sh --exclude=LICENSE . ; then echo "SCAN: FAIL"; exit 1; fi
echo "SCAN: PASS"
