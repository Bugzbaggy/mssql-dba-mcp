#!/usr/bin/env bash
# Leak scan: refuse to publish internal identifiers.
#
# This file is published, so it must not name anything it protects. An earlier
# version listed the organisation, product, schema and people names it guarded,
# and excluded itself from the scan; the scanner became the largest disclosure in
# the repo. The design is now split in two:
#
#   * STRUCTURAL classes (below) match the SHAPE of an internal identifier:
#     private addresses, cloud account and resource ids, real GUIDs, credential
#     tokens, ticket links, workstation profile paths, host- and listener-shaped
#     names, non-example e-mail addresses. No real value has to appear here.
#   * NAMED terms are supplied PRIVATELY: the LEAK_EXTRA_PAT (case-insensitive)
#     and LEAK_EXTRA_PAT_CS (case-sensitive) repository secrets in CI, or the
#     untracked files ci/leak-scan.private and ci/leak-scan.private-cs locally
#     (one extended regex per line, # comments allowed; both are gitignored).
#     When LEAK_REQUIRE_EXTRAS=true (CI sets it on pushes and same-repo pull
#     requests, where secrets are available) a missing half FAILS the run: a
#     class that is silently absent is worse than none, because the run still
#     says "clean".
#
# Shared VERBATIM across the public repos. Only comments may differ, and only to
# explain a repo-specific point; if you add a class, add it everywhere.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# --- Class 1: host, listener and cluster names, matched by SHAPE ---------------
# Real names follow <2-letter region>-<role>; the public examples deliberately use
# region1..regionN, listener.example.com and REGIONn-NODEn, which cannot match.
# The bare <xx>-<role> shape gets its own pass so the two generic words it would
# otherwise catch (AG-primary, db-primary) can be allowed by VALUE.
PAT_HOST='\b[A-Za-z]{2}-(db[0-9]+|primary|listener|nlb|lsnr|witness)\b'
ALLOW_HOST='^(ag|db)-'
PAT='\bd?ag-[a-z]{2}-[a-z0-9]+'
PAT="$PAT"'|\b[A-Z]{3,4}-[A-Z]{2,4}-[A-Z]{2}-DB[0-9]+\b|\b[a-z]{2,3}-(dev|stg|prd|uat)-db[0-9]+\b'
# Internal DNS suffixes: a region-code label followed by a private top-level label
# (it must be the LAST label, or node4.corp.example.com would match).
PAT="$PAT"'|\b[a-z]{2,5}[0-9]\.(ad|wc|lan|internal)([^.A-Za-z0-9-]|$)'

# --- Class 2: ticket links and workstation paths ------------------------------
# Any tracker link names a real project key, even on an example host.
PAT="$PAT"'|/browse/[A-Z][A-Z0-9]+-[0-9]+'
PAT="$PAT"'|[A-Za-z0-9]+_temporary_[a-z_]+'
# A real profile path names the author's workstation account. Placeholders and
# runner accounts are allowed by VALUE in their own pass.
PAT_HOME='[Uu]sers[\\/][A-Za-z][A-Za-z0-9._-]*[\\/]'
ALLOW_HOME='users[\\/](you|me|user|username|your-?name|public|default|runner|runneradmin)[\\/]'

# --- Class 3: business-sensitive disclosure -----------------------------------
PAT="$PAT"'|~?[0-9.]+ ?(B|bn|billion) rows'

# --- Class 4: credentials -------------------------------------------------------
PAT="$PAT"'|\bgh[pousr]_[A-Za-z0-9]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY'

# --- Class 5: cloud infrastructure identifiers --------------------------------
# AWS account ids are matched STRUCTURALLY (any bare 12-digit run) and allowed by
# VALUE in their own pass; listing real ids would publish them.
PAT_12='\b[0-9]{12}\b'
ALLOW_12='0{12}|1{12}|2{12}|3{12}|4{12}|5{12}|6{12}|7{12}|8{12}|9{12}|123456789012|0{9}[0-9]{3}'
# AWS resource ids. Placeholders spell words (vpc-0dev...), which are not hex.
PAT="$PAT"'|\b(vpc|subnet|sg|eni|ami|rtb|igw|acl)-[0-9a-f]{8,17}\b'
# RFC1918 addressing. All four octets are REQUIRED, or three-part version numbers
# (10.2.0) become false positives. Examples use 10.0.x.x placeholders or the
# RFC5737 documentation ranges; the block-start addresses name the range itself.
# The prefix carries its own octet count: 10 is ONE octet, 172.16-31 and 192.168
# are TWO. The previous form appended three octets to every prefix, so it only
# ever matched 172.x / 192.168.x as five-part strings - no real address in those
# ranges could fire. leak-scan.test.sh pins all three.
PAT_IP='\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'
ALLOW_IP='10\.0\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.0\.0|172\.16\.0\.0|192\.168\.[01]\.[0-9]{1,3}'
# GUIDs have no distinguishing shape, so every one is assumed real unless it is a
# placeholder (one repeated character, all zeros, dead-beef) or a known public
# constant: this module's manifest GUID and Windows' High Performance power plan.
# Repeated runs are enumerated: POSIX ERE has no backreferences, and GNU grep
# fails the whole pass on one ("Invalid back reference"), which would allow every
# GUID while reporting clean.
PAT_GUID='\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
ALLOW_GUID='00000000|11111111|22222222|33333333|44444444|55555555|66666666|77777777'
ALLOW_GUID="$ALLOW_GUID"'|88888888|99999999|aaaaaaaa|bbbbbbbb|cccccccc|dddddddd'
ALLOW_GUID="$ALLOW_GUID"'|eeeeeeee|ffffffff|dead-beef'
ALLOW_GUID="$ALLOW_GUID"'|c75286ed-c27d-4173-acff-6fb8cb8bca0d'
ALLOW_GUID="$ALLOW_GUID"'|8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'

# --- Class 6: e-mail addresses --------------------------------------------------
# Only documentation domains and no-reply identities may appear. Matched in its own
# pass so the allowed domains can be filtered by VALUE. Two shapes are not
# addresses at all: a token-in-URL (https://${TOKEN_VAR}@github.com) and a SQL
# LIKE pattern ('%@domain').
PAT_MAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
ALLOW_MAIL='@(([a-z0-9-]+\.)*example\.(com|org|net)|users\.noreply\.github\.com|anthropic\.com)$'
ALLOW_MAIL="$ALLOW_MAIL"'|^(noreply|no-reply)@|^%@'
ALLOW_MAIL_CS='^[A-Z][A-Z0-9_]*@github\.com$'

# --- Private named terms --------------------------------------------------------
load_private() {  # $1 = env value, $2 = fallback file
  if [ -n "$1" ]; then printf '%s' "$1"; return; fi
  [ -f "$2" ] && grep -vE '^\s*(#|$)' "$2" | paste -sd'|' -
}
EXTRA=$(load_private "${LEAK_EXTRA_PAT:-}" ci/leak-scan.private)
EXTRA_CS=$(load_private "${LEAK_EXTRA_PAT_CS:-}" ci/leak-scan.private-cs)
for half in EXTRA EXTRA_CS; do
  if [ -n "${!half}" ]; then
    echo "Leak scan: private ${half/EXTRA/extras} ACTIVE."
  elif [ "${LEAK_REQUIRE_EXTRAS:-false}" = "true" ]; then
    echo "::error::private ${half/EXTRA/extras} are REQUIRED on this run but missing - set the LEAK_${half/EXTRA/EXTRA_PAT} repository secret."
    exit 1
  else
    echo "Leak scan: private ${half/EXTRA/extras} INACTIVE (no secret, no ci/leak-scan.private file) - named terms are NOT checked."
  fi
done
[ -n "$EXTRA" ] && PAT="$PAT|$EXTRA"

# .superpowers/ is untracked agent scratch and dist/ is gitignored build output;
# grep has no gitignore awareness, so both are excluded explicitly. The private
# pattern files contain the very terms they define, and are never tracked.
EXCLUDES=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=bin
          --exclude-dir=obj --exclude-dir=dist --exclude-dir=.superpowers
          --exclude=leak-scan.sh --exclude='leak-scan.private*')

hits=$(grep -rniE "$PAT" . "${EXCLUDES[@]}" 2>/dev/null)
hits_cs=""
[ -n "$EXTRA_CS" ] && hits_cs=$(grep -rnE "$EXTRA_CS" . "${EXCLUDES[@]}" 2>/dev/null)

# Nothing under .superpowers/ may be TRACKED: the scan cannot see it, so a
# `git add -A` of agent scratch would publish whatever it holds unchecked.
tracked_sp=$(git ls-files '.superpowers/*' 2>/dev/null)
tracked_priv=$(git ls-files 'ci/leak-scan.private*' 2>/dev/null)

hits_12=$(grep -rnoE "$PAT_12" . "${EXCLUDES[@]}" 2>/dev/null | grep -vE ":($ALLOW_12)\$")
hits_ip=$(grep -rnoE "$PAT_IP" . "${EXCLUDES[@]}" 2>/dev/null | grep -vE ":($ALLOW_IP)\$")
hits_guid=$(grep -rnoE "$PAT_GUID" . "${EXCLUDES[@]}" 2>/dev/null | grep -viE ":[^:]*($ALLOW_GUID)")
# Value-filtered passes: the matched value is the last ':' field of grep -o. The
# allow regex reaches awk through ENVIRON, not -v: -v applies escape processing,
# which turns \. into . and silently widens the allow-list.
by_value() {  # $1 = allow regex, lower-case, matched against the lower-cased value
              # $2 = optional allow regex matched case-SENSITIVELY
  ALLOW="$1" ALLOW_CS="${2:-^\$^}" awk -F: \
    '{ if (tolower($NF) !~ ENVIRON["ALLOW"] && $NF !~ ENVIRON["ALLOW_CS"]) print }'
}
hits_host=$(grep -rnoiE "$PAT_HOST" . "${EXCLUDES[@]}" 2>/dev/null | by_value "$ALLOW_HOST")
hits_home=$(grep -rnoE "$PAT_HOME" . "${EXCLUDES[@]}" 2>/dev/null | by_value "$ALLOW_HOME")
hits_mail=$(grep -rnoE "$PAT_MAIL" . "${EXCLUDES[@]}" 2>/dev/null | by_value "$ALLOW_MAIL" "$ALLOW_MAIL_CS")
hits="$hits${hits_host:+
$hits_host}${hits_home:+
$hits_home}"
hits=$(printf '%s' "$hits" | sed '/^$/d')

if [ -n "$tracked_sp$tracked_priv" ]; then
  printf '%s\n' $tracked_sp $tracked_priv | sed 's/^/tracked but must not be: /'
  echo "::error::agent scratch or a private pattern file is tracked - git rm --cached it"
  exit 1
fi

if [ -n "$hits$hits_cs$hits_12$hits_ip$hits_guid$hits_mail" ]; then
  [ -n "$hits" ]      && echo "$hits"
  [ -n "$hits_cs" ]   && echo "$hits_cs"
  [ -n "$hits_12" ]   && echo "$hits_12"   | sed 's/$/  <- 12-digit run; if this is an AWS account id use a repeated-digit placeholder/'
  [ -n "$hits_ip" ]   && echo "$hits_ip"   | sed 's/$/  <- RFC1918 address; use 10.0.x.x or the RFC5737 range 192.0.2.x/'
  [ -n "$hits_guid" ] && echo "$hits_guid" | sed 's/$/  <- real-looking GUID; use a repeated-character or dead-beef placeholder/'
  [ -n "$hits_mail" ] && echo "$hits_mail" | sed 's/$/  <- e-mail outside the example domains/'
  echo "::error::internal identifier found - see matches above"
  exit 1
fi
echo 'Leak scan clean.'
