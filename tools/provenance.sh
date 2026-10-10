#!/bin/bash
# Provenance checks for openssl-1.1.1-continued (tools branch). Read-only: HTTPS GETs and git fetches only.
#
#   tools/provenance.sh --light   published refs equal releases.json; OpenSSL's public-by-SHA commits still
#                                 fetchable; every pinned source RPM still served by its blobstore URL
#   tools/provenance.sh --full    also: download and verify every pinned input (RPM signatures with Amazon's key,
#                                 1.1.1w's .asc), tree-check every tarball/* tag with git archive, re-import into
#                                 an empty repository and --compare with the published ids, and re-archive each
#                                 carry tag that has a release asset (sha256 must equal releases.json)
#
# Environment: FORK (default https://github.com/JohnsterID/openssl-1.1.1-continued.git), WORK (default a mktemp dir).
set -euo pipefail
MODE=${1:---light}
case "$MODE" in --light|--full) ;; *) echo "usage: $0 [--light|--full]" >&2; exit 2 ;; esac
TOOLS=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$TOOLS")
REL=$ROOT/releases.json
FORK=${FORK:-https://github.com/JohnsterID/openssl-1.1.1-continued.git}
UPSTREAM=https://github.com/openssl/openssl.git
WORK=${WORK:-$(mktemp -d)}
fail=0
say() { printf '%s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*"; fail=1; }

json() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); exec(sys.argv[2])' "$REL" "$1"; }

# 1. the fork's published refs equal releases.json
git ls-remote "$FORK" > "$WORK/ls-remote.txt"
while read -r ref want; do
  got=$(awk -v r="$ref" '$2==r"^{}"{p=$1} $2==r{c=$1} END{print (p?p:c)}' "$WORK/ls-remote.txt")
  if [ "$got" = "$want" ]; then say "ok   $ref $want"; else bad "$ref published ${got:-missing}, releases.json $want"; fi
done < <(json 'print("\n".join(" ".join(x) for x in d["fork"]["refs"].items()))')

# 2. OpenSSL's own post-1.1.1w commits are still fetchable by SHA (they are on no public ref)
git init -q "$WORK/up"
# GitHub occasionally fails a by-SHA fetch transiently (seen once on a hosted runner, 10 Oct 2026), so
# retry with backoff and show git's error before calling the commit gone.
for sha in $(json 'print(" ".join(d["upstream"].values()))'); do
  ok=0
  for try in 1 2 3; do
    if err=$(git -C "$WORK/up" fetch -q --depth=1 --no-tags "$UPSTREAM" "$sha" 2>&1); then ok=1; break; fi
    [ "$try" -lt 3 ] && sleep $((try * 10))
  done
  if [ "$ok" = 1 ]; then say "ok   upstream $sha$([ "$try" -gt 1 ] && printf " (attempt %s)" "$try")"
  else bad "upstream $sha no longer fetchable after 3 attempts: $(printf '%s' "$err" | tail -n 1)"; fi
done

# 3. the pinned source RPMs (content-addressed blobstore URLs)
while read -r name sha; do
  url="$(json 'print(d["al2_srpm_base"])')$sha/$name"
  if [ "$MODE" = --light ]; then
    if curl -fsSIL -o /dev/null "$url"; then say "ok   $name served"; else bad "$name not served at $url"; fi
  fi
done < <(json 'print("\n".join(" ".join([r["srpm"], r["srpm_sha256"]]) for r in d["releases"] if "srpm" in r))')

if [ "$MODE" = --full ]; then
  DL=$WORK/dl; mkdir -p "$DL/srpm" "$DL/keys"
  cp "$ROOT"/keys/*.asc "$DL/keys/"
  AL2KEY=$(json 'print(d["keys"]["amazon_linux_2"])')
  WKEY=$(json 'print(d["keys"]["openssl_1_1_1w"])')
  while read -r name sha tarball tsha; do
    if ! curl -fsSL -o "$DL/srpm/$name" "$(json 'print(d["al2_srpm_base"])')$sha/$name"; then bad "$name download"; continue; fi
    python3 -I "$TOOLS/import_release.py" rpm-verify "$DL/srpm/$name" --key "$DL/keys/amazon-linux-2-$AL2KEY.asc" \
      --expect-sha256 "$sha" > "$DL/srpm/$name.verify.json" || bad "$name rpm-verify"
    python3 -I "$TOOLS/import_release.py" rpm-extract "$DL/srpm/$name" "$tarball" "$DL/$tarball" > /dev/null
    if [ "$(sha256sum < "$DL/$tarball" | cut -d' ' -f1)" = "$tsha" ]; then say "ok   $tarball"; else bad "$tarball sha256"; fi
  done < <(json 'print("\n".join(" ".join([r["srpm"], r["srpm_sha256"], r["tarball"], r["tarball_sha256"]]) for r in d["releases"] if "srpm" in r))')
  W=$(json 'print(next(r["tarball"] for r in d["releases"] if r["version"]=="1.1.1w"))')
  curl -fsSL -o "$DL/$W" "https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/$W"
  curl -fsSL -o "$DL/$W.asc" "https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/$W.asc"
  GNUPGHOME=$(mktemp -d); export GNUPGHOME
  gpg --batch --quiet --import "$ROOT/keys/openssl-$WKEY.asc"
  if gpg --batch --status-fd 1 --verify "$DL/$W.asc" "$DL/$W" 2>/dev/null | grep -q "VALIDSIG $WKEY"; then say "ok   $W signature"
  else bad "$W signature"; fi
  # tree-check every tarball/* tag against its tarball (git archive, export-ignore applied)
  git clone -q --bare --no-tags "$FORK" "$WORK/fork.git"
  git -C "$WORK/fork.git" fetch -q --no-tags "$FORK" 'refs/tags/*:refs/tags/*'
  while read -r v tarball; do
    if python3 -I "$TOOLS/import_release.py" tree-check "$WORK/fork.git" "tarball/$v" "$DL/$tarball" --git-archive > /dev/null; then
      say "ok   tarball/$v tree"; else bad "tarball/$v differs from $tarball"; fi
  done < <(json 'print("\n".join(" ".join([r["version"], r["tarball"]]) for r in d["releases"] if "srpm" in r))')
  # re-import from scratch: identical commit ids. The jz1 carry is rebuilt from its two published fix
  # commits (patches taken from the fork), so its version commit must come out with the published id.
  mkdir -p "$DL/carry"
  git -C "$WORK/fork.git" format-patch -q --zero-commit -o "$DL/carry" tarball/1.1.1zi..carry/1.1.1zi-jz1~1
  git init -q "$WORK/reimport"
  python3 -I "$TOOLS/build_mirror.py" --repo "$WORK/reimport" --fetch-upstream "$UPSTREAM" > /dev/null
  MIRROR_DL=$DL MIRROR_REPO=$WORK/reimport python3 -I "$TOOLS/build_mirror.py" --result "$WORK/reimport.json" > /dev/null
  git -C "$WORK/reimport" fetch -q --no-tags "$FORK" 'refs/tags/carry/*:refs/published/carry/*'
  if python3 -I "$TOOLS/build_mirror.py" --compare "$WORK/reimport.json" --refs "$WORK/ls-remote.txt" --repo "$WORK/reimport" > "$WORK/compare.json"; then
    say "ok   re-import ids equal the published ones"; else bad "re-import differs (see $WORK/compare.json)"; fi
  # carry release assets
  while read -r tag prefix asset sha; do
    if ! git -C "$WORK/fork.git" rev-parse -q --verify "$tag^{commit}" >/dev/null; then bad "$tag not published"; continue; fi
    got=$(git -C "$WORK/fork.git" archive --format=tar --prefix="$prefix/" "$tag" | gzip -n -9 | sha256sum | cut -d' ' -f1)
    if [ "$got" = "$sha" ]; then say "ok   $tag -> $asset"; else bad "$tag archive $got != $sha"; fi
  done < <(json 'print("\n".join(" ".join([t, a["prefix"], a["asset"], a["sha256"]]) for t, a in d["carry_assets"].items()))')
fi
if [ "$fail" = 0 ]; then say "provenance $MODE: PASS"; else say "provenance $MODE: FAIL"; fi
exit "$fail"
