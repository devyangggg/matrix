# Sample Go repository (template)

Source of the public demo repo `https://github.com/<org>/matrix-hello` (AGENTS §10). Builders clone
from GitHub, so this folder is only the template: `scripts/make_sample_repo.sh DIR` turns it into a
git repository with every demo tag, ready to push.

| Tag | Purpose | Expected |
|---|---|---|
| `v1.2.0` .. `v1.2.5` | Demo scenes (one tag per scene, RFC rev 5 §9.2); identical code, version from ldflags | `CERTIFIED` |
| `v0.9.0-broken` | Compile error (undefined name) | `BUILD_FAILED`, exit 5 |
| `v0.9.1-norecipe` | No `matrix.toml` | every builder abstains: `PENDING`, exit 3 |

`matrix.toml.in` is the recipe; the script writes it as `matrix.toml` with `@TAG@` replaced.
[examples/faults/backdoor.patch](../faults/backdoor.patch) applies to every `v1.2.x` tag.
