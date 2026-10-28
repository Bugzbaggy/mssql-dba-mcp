#!/usr/bin/env bash
# Self-test for ci/leak-scan.sh: every class must FIRE on a planted value, and every
# documented placeholder must PASS. Without this, an edit that breaks one regex
# (a stray backreference, an over-eager allow-list) leaves the gate printing
# "clean" while checking nothing.
#
# Fixtures are assembled from fragments at run time ("10.12"".34.56") so this file
# never contains a matching value itself and is safe to leave in the scanned tree.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
scanner="$here/leak-scan.sh"
fail=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkrepo() {  # $1 = dir; creates a git repo holding a copy of the scanner
  mkdir -p "$1/ci" && cp "$scanner" "$1/ci/leak-scan.sh"
  git -C "$1" init -q && git -C "$1" config user.email t@example.com && git -C "$1" config user.name t
}
run() {  # $1 = dir; remaining args = env assignments
  local d="$1"; shift
  (cd "$d" && env "$@" bash ci/leak-scan.sh 2>&1); echo "rc=$?"
}
expect() {  # $1 = label, $2 = output, $3 = needle that must appear
  if printf '%s' "$2" | grep -qF -- "$3"; then echo "ok   - $1"; else echo "FAIL - $1 (missing: $3)"; fail=1; fi
}
refute() {  # $1 = label, $2 = output, $3 = needle that must NOT appear
  if printf '%s' "$2" | grep -qF -- "$3"; then echo "FAIL - $1 (unexpected: $3)"; fail=1; else echo "ok   - $1"; fi
}

# --- 1. every class fires ------------------------------------------------------
pos="$work/pos"; mkrepo "$pos"
{
  echo "host:    xy""-db1 and ag-x""y-lsnr"
  echo "ticket:  https://tracker.example.com/browse/""ABC-123"
  echo 'path:    C:\Users\''jdoe\Documents'
  echo "ip:      10.12"".34.56 and 172.20"".1.2 and 192.168"".7.8"
  echo "acct:    1234""12341234"
  echo "guid:    3f2b1c4d-5e6f-4a1b-""9c8d-7e6f5a4b3c2d"
  echo "aws:     vpc-0a1b2c""3d4e5f60718"
  echo "mail:    someone@""corp-mail.io"
  echo "token:   ghp_""abcdefghijklmnopqrstuvwxyz0123456789"
  echo "named:   Acme""Corp ZZ""-12"
} > "$pos/leaky.txt"
out=$(run "$pos" LEAK_EXTRA_PAT='acme''corp' LEAK_EXTRA_PAT_CS='\bZZ''-[0-9]+')
expect "exit status is non-zero"        "$out" "rc=1"
expect "host shape"                     "$out" "xy""-db1"
expect "listener shape"                 "$out" "ag-x""y-lsnr"
expect "ticket link"                    "$out" "/browse/""ABC-123"
expect "workstation profile path"       "$out" 'Users\''jdoe\'
expect "RFC1918 10/8"                   "$out" "10.12"".34.56"
expect "RFC1918 172.16/12"              "$out" "172.20"".1.2"
expect "RFC1918 192.168/16"             "$out" "192.168"".7.8"
expect "12-digit account id"            "$out" "1234""12341234"
expect "real-looking GUID"              "$out" "3f2b1c4d-5e6f-4a1b-""9c8d-7e6f5a4b3c2d"
expect "AWS resource id"                "$out" "vpc-0a1b2c""3d4e5f60718"
expect "non-example e-mail"             "$out" "someone@""corp-mail.io"
expect "credential token"               "$out" "ghp_""abcdefghij"
expect "private term (case-insens.)"    "$out" "Acme""Corp"
expect "private term (case-sens.)"      "$out" "ZZ""-12"

# --- 2. documented placeholders pass -------------------------------------------
neg="$work/neg"; mkrepo "$neg"
{
  echo "region1-node1 REGION3-NODE1 ag-region1-lsnr listener.example.com"
  echo "AG-primary alias; MySQL hostname = 'db-primary'"
  echo 'HEALTHCHECK_REPORT_DIR=C:\Users\you\Documents\reports'
  echo "10.0.1.9 192.168.0.0 172.16.0.0 version 10.2.0"
  echo "000000000001 111111111111 123456789012"
  echo "00000000-0000-0000-0000-000000000000 deadbeef-dead-beef-dead-beefdeadbeef"
  echo "opensource@example.com User@Example.com ci-bot@users.noreply.github.com"
  echo 'git clone https://${GITHUB_ACCESS_TOKEN}@github.com/owner/repo.git'
  echo "WHERE email LIKE '%@gmail.com'"
} > "$neg/clean.txt"
out=$(run "$neg" LEAK_EXTRA_PAT='acme''corp' LEAK_EXTRA_PAT_CS='\bZZ''-[0-9]+')
expect "placeholders pass"              "$out" "Leak scan clean."
refute "no error on placeholders"       "$out" "::error::"

# --- 3. CI refuses to run without the private halves ---------------------------
out=$(run "$neg" LEAK_REQUIRE_EXTRAS=true)
expect "missing extras fail closed"     "$out" "rc=1"
expect "missing extras are named"       "$out" "REQUIRED on this run"

# --- 4. a tracked private pattern file is refused ------------------------------
echo 'acme''corp' > "$neg/ci/leak-scan.private"
git -C "$neg" add -f ci/leak-scan.private
out=$(run "$neg")
expect "tracked private file refused"   "$out" "tracked but must not be"

[ "$fail" -eq 0 ] && echo "leak-scan self-test: all passed" || echo "leak-scan self-test: FAILURES"
exit "$fail"
