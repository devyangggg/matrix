#!/usr/bin/env bash
# Build the sample Go repository with every demo tag (AGENTS §10, RFC rev 5 §9.2), ready to push:
#
#   scripts/make_sample_repo.sh /tmp/matrix-hello
#   cd /tmp/matrix-hello && git remote add origin https://github.com/<org>/matrix-hello.git
#   git push -u origin main --tags
#
# Tags:
#   v1.2.0 .. v1.2.5   identical code; only the version in matrix.toml's ldflags differs
#   v0.9.0-broken      compile error   -> BUILD_FAILED (exit 5)
#   v0.9.1-norecipe    no matrix.toml  -> BAD_RECIPE, every builder abstains -> PENDING (exit 3)
# examples/faults/backdoor.patch applies to every v1.2.x tag.
set -euo pipefail

out="${1:?usage: make_sample_repo.sh DIR}"
src="$(cd "$(dirname "$0")/../examples/sample-repo" && pwd)"
if [ -e "$out" ]; then
    echo "make_sample_repo.sh: $out already exists; choose a new directory" >&2
    exit 1
fi

mkdir -p "$out"
cp -R "$src/go.mod" "$src/cmd" "$out/"
cd "$out"
find . -type d -exec chmod 755 {} + && find . -type f -exec chmod 644 {} +  # not 755 from NTFS
git init -q -b main
git config user.name "matrix demo"
git config user.email "matrix-demo@example.invalid"

recipe() { sed "s/@TAG@/$1/" "$src/matrix.toml.in" > matrix.toml; }
commit_tag() { git add -A && git commit -q -m "$1" && git tag "$1"; }

for tag in v1.2.0 v1.2.1 v1.2.2 v1.2.3 v1.2.4 v1.2.5; do
    recipe "$tag"
    commit_tag "$tag"
done

# A deterministic compile error: an undefined name.
recipe v0.9.0-broken
# Portable on GNU and BSD/macOS sed: no in-place flag; write a temp file, then move it.
sed 's/fmt.Println("hello from matrix " + version)/fmt.Println("hello from matrix " + versio)/' \
    cmd/hello/main.go > cmd/hello/main.go.tmp && mv cmd/hello/main.go.tmp cmd/hello/main.go
commit_tag v0.9.0-broken
git checkout -q v1.2.5 -- cmd/hello/main.go

# No recipe at all.
git rm -q matrix.toml
commit_tag v0.9.1-norecipe

# Leave main at the last good state.
recipe v1.2.5
git add -A && git commit -q -m "main: restore the recipe"

echo "tags and commits (use these with matrix release --commit):"
for tag in v1.2.0 v1.2.1 v1.2.2 v1.2.3 v1.2.4 v1.2.5 v0.9.0-broken v0.9.1-norecipe; do
    printf '  %-16s %s\n' "$tag" "$(git rev-parse "$tag^{commit}")"
done
