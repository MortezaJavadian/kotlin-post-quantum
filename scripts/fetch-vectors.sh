#!/usr/bin/env bash
#
# Fetch the NIST ACVP and Wycheproof test vectors this suite validates against.
#
# The vectors are not vendored: the full mirror is roughly 750 MB and most of it is
# SLH-DSA and Falcon, which this library does not implement. So this does a pinned,
# shallow, blobless, sparse checkout of only the suites the tests actually read.
#
# Pinned to the exact commit noble-post-quantum records for its own submodule, so the
# vectors this library is judged against are byte-for-byte the ones the reference
# implementation is judged against. Bump PIN only together with a re-run of the suite.
#
#   ./scripts/fetch-vectors.sh            # fetch into ./test-vectors
#   ./scripts/fetch-vectors.sh /some/dir  # fetch elsewhere
#
set -euo pipefail

REPO_URL="https://github.com/paulmillr/acvp-vectors.git"
PIN="2e9216ceafb854d7bc113088a2f8b043654226a8"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-$ROOT/test-vectors}"

# The suites the Kotlin suite reads. Non-cone sparse patterns (gitignore syntax).
# SHA3/SHAKE are globs because the ACVP suite directories carry a revision suffix that
# changes between ACVP-Server releases; whatever matches is what the hash tests use.
PATTERNS=(
  "/utils.js"
  "/package.json"
  "/acvp/ML-KEM-keyGen-FIPS203/"
  "/acvp/ML-KEM-encapDecap-FIPS203/"
  "/acvp/ML-DSA-keyGen-FIPS204/"
  "/acvp/ML-DSA-sigGen-FIPS204/"
  "/acvp/ML-DSA-sigVer-FIPS204/"
  "/acvp/SHA3-*/"
  "/acvp/SHAKE-*/"
  "/wycheproof/testvectors_v1/mlkem_*"
  "/wycheproof/testvectors_v1/mldsa_*"
)

echo "==> destination: $DEST"
echo "==> pin:         $PIN"

if [ -e "$DEST/.git" ]; then
  echo "==> reusing existing checkout"
else
  mkdir -p "$DEST"
  git -C "$DEST" init -q
  git -C "$DEST" remote add origin "$REPO_URL"
fi

git -C "$DEST" config core.sparseCheckout true
git -C "$DEST" sparse-checkout init --no-cone
git -C "$DEST" sparse-checkout set "${PATTERNS[@]}"

# --filter=blob:none downloads the commit and tree objects but no file contents; the
# sparse checkout then pulls blobs on demand, so only the matched paths ever transfer.
echo "==> fetching (this is the slow part; a few hundred MB)"
git -C "$DEST" fetch -q --depth 1 --filter=blob:none origin "$PIN"
git -C "$DEST" checkout -q --detach FETCH_HEAD

got="$(git -C "$DEST" rev-parse HEAD)"
if [ "$got" != "$PIN" ]; then
  echo "!! checked out $got, expected $PIN" >&2
  exit 1
fi

echo
echo "==> ACVP suites available upstream at this pin:"
git -C "$DEST" ls-tree --name-only HEAD acvp/ | sed 's|^acvp/||; s|/$||; s|^|      |'

echo
echo "==> fetched:"
for d in "$DEST/acvp"/*/; do
  [ -d "$d" ] || continue
  n=$(find "$d" -type f | wc -l | tr -d ' ')
  printf '      %-34s %s files, %s\n' "$(basename "$d")" "$n" "$(du -sh "$d" | cut -f1)"
done
if [ -d "$DEST/wycheproof/testvectors_v1" ]; then
  n=$(find "$DEST/wycheproof/testvectors_v1" -type f | wc -l | tr -d ' ')
  printf '      %-34s %s files, %s\n' "wycheproof/testvectors_v1" "$n" \
    "$(du -sh "$DEST/wycheproof/testvectors_v1" | cut -f1)"
fi
echo
echo "==> total: $(du -sh "$DEST" | cut -f1)"
echo "==> done. Run the suite with: ./gradlew test"
