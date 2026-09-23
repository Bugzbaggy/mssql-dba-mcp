#!/usr/bin/env bash
# Leak scan: refuse to publish internal/proprietary identifiers.
#
# The PATTERN SET below is shared VERBATIM across the four public repos. Keep it
# that way. The 2026-09 review found a colleague's surname gated in one repo and
# missed in another purely because each repo carried its own hand-edited inline
# pattern, and a later pass found this script itself two whole classes behind in
# one repo. Only comments may differ, and only to explain a repo-specific
# exclusion; if you add a class, add it to all four in the same change.
#
# It excludes ITSELF from the scan, since it necessarily contains the terms it
# looks for. Everything else in the tree is scanned, including .github/.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# --- Class 1: infrastructure hostnames / domains ------------------------------
# Node and region naming is matched by SHAPE, not by listing the live hostnames.
# The shapes below (<region>-db<n>, <region>-primary/listener/nlb) are what the
# anonymised examples deliberately avoid — they use region1..regionN and
# <regionN>-primary — so matching the shape catches a real name without this
# file having to contain one.
PAT='\b(sg|uk|us|id|st)-(db[0-9]|primary|listener|nlb)\b|sg/id/uk/us|\bID-UK-US\b'
# A bare region code used as a region ("on SG", "For UK that is") is matched in
# the case-SENSITIVE pass (see PAT_CS) — the anchoring preposition is what stops
# it firing on an ISO country code in test data, but under -i it also matched the
# English "fix this for us". Region codes are always written upper-case.

# Staging resource groups use a 'stg' prefix, one letter longer than the 'st'
# the pattern above matches, with suffixes the db/primary/listener/nlb list does
# not cover. Two publishable repos were carrying such a name before this class
# existed. Matched by shape, like the rest of this class, so no real name has to
# appear here — this file excludes itself from the scan, so anything written in
# it ships unchecked.
PAT="$PAT"'|\bstg-(ag|dbcluster|lsnr)[0-9]+\b'

# --- Class 2: company / product / vendor --------------------------------------
PAT="$PAT"'|wavecell|8x8|cpaas|CPAAS|MessageSphere|WC_[A-Za-z_]+|govern8'
PAT="$PAT"'|\bPASA\b|\bPasa\b|pasa-'
PAT="$PAT"'|[Cc]arbon [Bb]lack|\bSimba\b|BigQuery|_BQ_'

# --- Class 3: people and personal paths ---------------------------------------
# The repo owner's own name is allowed (LICENSE / AUTHORS). Colleagues are not.
#
# Colleagues' surnames are NOT listed here. This file excludes itself from the
# scan, so whatever is written here ships unscanned — a public repo carrying a
# list of real people's surnames is itself the disclosure, and a worse one than
# the regression it guards against, since a name that never leaked would be
# published by the guard. A hard-coded list also only ever covered the four
# people who had already leaked once; a fifth colleague was never protected.
# Supply them privately instead, via LEAK_EXTRA_PAT (see below).
PAT="$PAT"'|[Uu]sers[\\/]rbagasbas'
PAT="$PAT"'|[A-Za-z0-9]+_temporary_[a-z_]+'

# --- Class 4: ticket keys -----------------------------------------------------
# Ticket keys are DIGIT-suffixed. Do NOT broaden the suffix to [0-9A-Za-z]+:
# under grep -i that matches legitimate names like msg-ops, msg-reader, msg-apse1.
PAT="$PAT"'|\b(DBV|MSG|DBA)-[0-9]+\b|\bCPENG-[A-Za-z0-9]+\b'

# --- Class 5: real schema objects ---------------------------------------------
PAT="$PAT"'|\bSmsLog\b|\bsmsLog\b|\bStatSmsLog\b|\bSmsTrack\b'
PAT="$PAT"'|SmsLogRegionLookup|DimSmsStatus|\bAccountWallet\b'

# --- Class 6: business-sensitive disclosure -----------------------------------
# NOTE: MSISDN is deliberately NOT gated - it is a standard ITU-T E.164 term and a
# legitimate stored-procedure parameter name, not a proprietary identifier.
PAT="$PAT"'|~?[0-9.]+ ?(B|bn|billion) rows'

# --- Class 7: cloud infrastructure identifiers --------------------------------
# AWS account ids are matched STRUCTURALLY — any bare 12-digit run — rather than
# by listing the real ones. Listing them published them, and only ever caught
# those four; this catches every AWS account id, including accounts that did not
# exist when the list was written. Documented placeholders are allowed through
# in the ALLOW_12 pass below.
# Scanned in its own pass (below) so placeholder ids can be allowed by VALUE.
PAT_12='\b[0-9]{12}\b'
# AWS resource ids. Real ones map the estate when read next to an account id.
# The hex charset is what makes this safe to match structurally: placeholders
# spell words (vpc-0dev..., subnet-0stg0private1), which are not valid hex and
# so cannot match.
PAT="$PAT"'|\b(vpc|subnet|sg|eni|ami|rtb|igw|acl)-[0-9a-f]{8,17}\b'
# Internal RFC1918 addressing. Examples must use RFC5737 doc ranges (192.0.2.x).
# 172.16-31 is RFC1918 too and was previously missed, so a 172.x internal address
# passed the gate. All four octets are REQUIRED: making the last one optional
# turns every three-part version number (10.2.0, 10.7.2) into a false positive,
# which is how this pattern first went in. The RFC1918 block-start addresses are
# allowed by value — they name the range itself, as cited in network docs, and
# are not anyone's host.
# Scanned in its own pass (below) so the block-start addresses can be allowed by
# VALUE; filtering the main pass by line would drop the whole line and could hide
# a real address that shared it.
PAT_IP='\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
ALLOW_IP='10\.0\.0\.0|192\.168\.0\.0|172\.16\.0\.0'
# GUIDs. A real one lifted from a cluster log, an Entra app or a subscription is
# an internal identifier, and nothing else in this gate can see it — a GUID has
# no distinguishing shape. Scanned in its own pass and allowed by VALUE, because
# the legitimate ones are few and nameable:
#   * a hex run that is one repeated character, or all zeros, or spells dead-beef
#     — the placeholder conventions used in examples and test fixtures;
#   * this module's own manifest GUID, which is its public identity;
#   * Microsoft's well-known High Performance power-scheme GUID, which is the
#     same constant on every Windows machine.
# Anything else is assumed real until someone adds it here deliberately.
PAT_GUID='\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
# Repeated-character runs are enumerated rather than written as a backreference
# ((.)\1{7}): grep -E is POSIX ERE, which has no backreferences, and GNU grep
# does not silently ignore one — it fails the whole pass with "Invalid back
# reference". The filter then produces nothing and every GUID is allowed, so the
# gate reports clean while checking nothing. Fail-open, in a leak gate.
ALLOW_GUID='00000000|11111111|22222222|33333333|44444444|55555555|66666666|77777777'
ALLOW_GUID="$ALLOW_GUID"'|88888888|99999999|aaaaaaaa|bbbbbbbb|cccccccc|dddddddd'
ALLOW_GUID="$ALLOW_GUID"'|eeeeeeee|ffffffff|dead-beef'
ALLOW_GUID="$ALLOW_GUID"'|c75286ed-c27d-4173-acff-6fb8cb8bca0d'
ALLOW_GUID="$ALLOW_GUID"'|8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'

# --- Class 8: pre-anonymization schema prefixes / product names --------------
# The 2026-09 pass renamed cp./ms./sms. -> core./svc./msg. and ChatApps/Omnishield
# -> Channels/Protection. Gate against the old names coming back. This is checked
# case-insensitively below (product names), except the schema-prefix half, which
# is intentionally run case-SENSITIVE in a separate pass (see PAT_CS) — under -i
# the [A-Z] anchor would stop distinguishing a real schema reference (cp.Account)
# from the sys.dm_exec_cached_plans "cp" DMV alias (cp.plan_handle, cp.objtype,
# cp.size_in_bytes, cp.usecounts), which is standard idiom, not a leak.
PAT="$PAT"'|[Oo]mnishield|[Vv]erif8|[Cc]hatApps|[Jj]itsi'
PAT_CS='\b(cp|ms|sms|map|rt|ipm|cls|tmpl)\.[A-Z][A-Za-z_]+'
PAT_CS="$PAT_CS"'|\b(on|in|for|On|In|For) (SG|UK|US|ID)\b'

# --- Private extras (optional) ------------------------------------------------
# Anything whose VALUE is itself the disclosure — colleagues' surnames, live
# hostnames, an internal AD domain — belongs here, not in the classes above,
# because this file is published. Supply it as an extended regex, either in the
# environment or in an untracked file next to this script:
#
#   LEAK_EXTRA_PAT='\bSomeSurname\b|internal-host-1|corp\.example\.ad'
#   ci/leak-scan.private        (add to .gitignore; one regex, comments with #)
#
# In CI, set it as a repository secret and export it for this step. The status is
# printed on every run: a class that is silently absent is worse than no class,
# because the run still says "clean".
if [ -z "${LEAK_EXTRA_PAT:-}" ] && [ -f "$(dirname "$0")/leak-scan.private" ]; then
  LEAK_EXTRA_PAT=$(grep -vE '^\s*(#|$)' "$(dirname "$0")/leak-scan.private" | paste -sd'|' -)
fi
if [ -n "${LEAK_EXTRA_PAT:-}" ]; then
  PAT="$PAT|$LEAK_EXTRA_PAT"
  echo "Leak scan: private extras ACTIVE."
else
  echo "Leak scan: private extras INACTIVE (LEAK_EXTRA_PAT unset, no ci/leak-scan.private)."
fi

# .superpowers/ holds untracked SDD scratch (progress notes, task reports) that
# legitimately discusses these terms; grep has no gitignore awareness, so it
# must be excluded explicitly rather than relying on untracked-file skipping.
#
# dist/ is gitignored TypeScript build output, so it is never published; a local
# build made before the rename leaves stale strings there and grep, having no
# gitignore awareness, would report them as leaks.
EXCLUDES=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=bin
          --exclude-dir=obj --exclude-dir=dist --exclude-dir=.superpowers
          --exclude=leak-scan.sh)

hits=$(grep -rniE "$PAT" . "${EXCLUDES[@]}" 2>/dev/null)
hits_cs=$(grep -rnE "$PAT_CS" . "${EXCLUDES[@]}" 2>/dev/null)

# Nothing under .superpowers/ may be TRACKED. The scan excludes that directory —
# it is agent scratch that legitimately discusses every term above — which means
# the one directory the scanner is blind to is also the one most likely to hold a
# full before/after rename mapping. A `git add -A` put exactly such a file into a
# commit once, and no class above could have caught it. Checked separately, from
# the index rather than the filesystem.
tracked_sp=$(git ls-files '.superpowers/*' 2>/dev/null)

# 12-digit runs are scanned separately so documented placeholder account ids can
# be allowed through by VALUE. Filtering the main pass by line would instead drop
# a whole line, hiding a real leak that shared a line with a placeholder.
# Any digit repeated twelve times is the documented placeholder convention, so
# allow the whole family rather than the four values that happened to be in use —
# a fifth account written as 444444444444 was otherwise reported as a leak.
ALLOW_12='0{12}|1{12}|2{12}|3{12}|4{12}|5{12}|6{12}|7{12}|8{12}|9{12}|123456789012'
hits_12=$(grep -rnoE "$PAT_12" . "${EXCLUDES[@]}" 2>/dev/null \
            | grep -vE ":($ALLOW_12)\$")
hits_ip=$(grep -rnoE "$PAT_IP" . "${EXCLUDES[@]}" 2>/dev/null \
            | grep -vE ":($ALLOW_IP)\$")
# The allow-list is matched case-insensitively and as a SUBSTRING of the guid,
# so the repeated-character and dead-beef conventions match wherever they sit.
hits_guid=$(grep -rnoE "$PAT_GUID" . "${EXCLUDES[@]}" 2>/dev/null \
            | grep -viE ":[^:]*($ALLOW_GUID)")

if [ -n "$tracked_sp" ]; then
  echo "$tracked_sp" | sed 's/^/tracked agent scratch: /'
  echo "::error::files under .superpowers/ are tracked - this directory is EXCLUDED from the leak scan, so nothing in it is checked. Untrack them: git rm --cached -r .superpowers"
  exit 1
fi

if [ -n "$hits" ] || [ -n "$hits_cs" ] || [ -n "$hits_12" ] || [ -n "$hits_ip" ] || [ -n "$hits_guid" ]; then
  [ -n "$hits" ] && echo "$hits"
  [ -n "$hits_cs" ] && echo "$hits_cs"
  [ -n "$hits_12" ] && echo "$hits_12" | sed 's/$/  <- 12-digit run; if this is an AWS account id use a repeated-digit placeholder/'
  [ -n "$hits_ip" ] && echo "$hits_ip" | sed 's/$/  <- RFC1918 address; examples must use the RFC5737 doc range 192.0.2.x/'
  [ -n "$hits_guid" ] && echo "$hits_guid" | sed 's/$/  <- real-looking GUID; use a repeated-character or dead-beef placeholder/'
  echo "::error::internal identifier found - see matches above"
  exit 1
fi
echo 'Leak scan clean.'
