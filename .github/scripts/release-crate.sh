#!/usr/bin/env bash
set -euo pipefail

CRATE="$1"
CARGO_TOML="${CRATE}/Cargo.toml"
CHANGELOG="${CRATE}/CHANGELOG.md"

VERSION=$(grep -m1 '^version' "$CARGO_TOML" | sed 's/version = "\(.*\)"/\1/')
TAG="${CRATE}/${VERSION}"
echo "Detected version: $VERSION  (tag: $TAG)"

if git tag -l "$TAG" | grep -q .; then
  echo "Tag $TAG already exists — skipping release."
  exit 0
fi

ESCAPED=$(printf '%s' "$VERSION" | sed 's/\./\\./g')
if ! grep -qE "^# ${ESCAPED}( |$)" "$CHANGELOG"; then
  echo "ERROR: No CHANGELOG entry found for version $VERSION in $CHANGELOG"
  echo "Expected a line matching: # ${VERSION} (optional date)"
  exit 1
fi

NOTES=$(awk "/^# ${ESCAPED}( |$)/{found=1; next} found && /^# /{exit} found{print}" "$CHANGELOG")
NOTES=$(printf '%s\n' "$NOTES" | sed '/./,$!d')
NOTES=$(printf '%s\n' "$NOTES" | sed -e :a -e '/^\n*$/{$d;N;ba}')

git tag "$TAG"
PUSH_OUTPUT=$(git push origin "$TAG" --porcelain 2>&1) || {
  if printf '%s' "$PUSH_OUTPUT" | grep -q "already exists"; then
    echo "Tag $TAG was already pushed by a concurrent run — skipping release."
    exit 0
  fi
  echo "ERROR: Failed to push tag $TAG"
  printf '%s\n' "$PUSH_OUTPUT"
  exit 1
}
echo "Pushed tag: $TAG"

NOTES_FILE=$(mktemp)
printf '%s\n' "$NOTES" > "$NOTES_FILE"

gh release create "$TAG" \
  --title "${CRATE} ${VERSION}" \
  --notes-file "$NOTES_FILE"

rm -f "$NOTES_FILE"
echo "Created release: ${CRATE} ${VERSION}"

gh workflow run publish.yml --ref main -f tag="$TAG"
echo "Triggered publish workflow for $TAG"
