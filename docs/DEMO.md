# Matrix demo runbook

The six scenes from [RFC §9.2](../Matrix_RFC_001.md), about 4 minutes on stage. Every command
below is copy-paste. Values marked `TBD` come from [AGENTS.md §4 and §10](../AGENTS.md) and must
be filled in before the rehearsal (X2).

The runbook is written for the **single-machine compose network** (8 builders, demo profile).
On the 4-laptop tinc network the commands are the same, without the `docker compose run --rm cli`
prefix. See [§8](#8-on-the-4-laptop-network).

## 0. Before the demo (once, about 15 minutes)

On Linux or WSL2, from the repo root:

```bash
cp .env.example .env                       # set MATRIX_DATA (absolute), MATRIX_UID/GID, DOCKER_GID
. ./.env && mkdir -p "$MATRIX_DATA" dist

export REPO=https://github.com/<org>/matrix-hello                      # H3
export IMAGE=golang@sha256:TBD                                         # H4, linux/amd64 digest
python scripts/dev_genesis.py --out dev --addrs compose --profile demo --repo "$REPO" --image "$IMAGE"
docker pull --platform linux/amd64 "$IMAGE"
docker compose build

# Tag commits (the CLI signs the commit, not an annotated tag object).
# Prefer the peeled ref; use the tag ref itself only for lightweight tags.
c() {
  local ref
  ref=$(git ls-remote --exit-code "$REPO" "refs/tags/$1^{}") ||
    ref=$(git ls-remote --exit-code "$REPO" "refs/tags/$1") || return 1
  printf '%s\n' "${ref%%[[:space:]]*}"
}
C120=$(c v1.2.0) && C121=$(c v1.2.1) && export C120 C121
echo "$C120 $C121"                         # two 40-hex commit SHAs, else stop and fix the repo

# Shorthand used by every scene
alias mx='docker compose run --rm cli'
export PIN=$(cat dev/genesis.sha256)
```

Expected hashes (AGENTS §10, fill in after B1):

| Name | Value |
|---|---|
| `H120` honest `v1.2.0` | `TBD` |
| `H121` honest `v1.2.1` | `TBD` |
| `BAD121` backdoored `v1.2.1` | `TBD` |

Put `BACKDOOR_HASH=<BAD121>` in `.env` (scene 3 reads it).

**Offline verify machine (H9).** Before disconnecting, copy `dev/genesis.json` to
`~/.matrix/genesis.json` and `dev/genesis.sha256` to `~/.matrix/genesis.sha256` on it.
From a reviewed Matrix source checkout there, install the verifier and set `REPO`
to the same trusted canonical URL used above (H3):

```bash
pip install -e .
export REPO=https://github.com/<org>/matrix-hello
```

Keep its network **off** during scenes 1 and 4. `matrix verify` never opens a socket; its
`--repo "$REPO"` argument must come from the consumer, not from an untrusted certificate.

## 1. Reset (between scenes)

A request ID is the hash of `(repo, commit, tag)`. Releasing the same tag twice returns the
first result, so **reset before every scene that reuses a tag** (scenes 3, 5, 6). A reset takes
about 10 s and the next build about 45 s.

```bash
docker compose down
sudo rm -rf "$MATRIX_DATA"/builder*        # db, logs, artifacts of all 8 builders
docker compose up -d                       # every builder honest again
docker compose ps                          # 8 x "healthy" after ~10 s
```

Open the TUI in a second terminal and leave it running for the whole demo:

```bash
docker compose run --rm cli tui            # keys: b builders, r releases, Enter detail, l log, e evidence, q quit
```

Builders screen: 8 rows, all `reachable yes`, `genesis match`.

## 2. Scene 1: happy path (`v1.2.0`)

```bash
mx release --repo "$REPO" --tag v1.2.0 --commit "$C120" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.0 --output hello
echo "exit $?"
```

Expected after certification (the number and order of votes received vary):

```
request <64 hex> https://github.com/<org>/matrix-hello@v1.2.0
request <64 hex>
verdict AGREED <H120>
  builder1     laptopA    <result or ->     <ok or ->
  ...                           (8 builder rows; unreported results show "-")
CERTIFIED <H120> -> dist/v1.2.0/hello
exit 0
```

TUI Releases: quorum reaches `3/3` and verdict `AGREED`; attestations may continue to
fill toward `8/8` as builders finish. The CLI stops once it has a certified quorum,
so some printed builder rows may not yet have an attestation.

Copy `dist/v1.2.0/hello` and `dist/v1.2.0/hello.matrix.json` to the offline machine (USB stick), then:

```bash
matrix verify hello --cert hello.matrix.json --repo "$REPO" --tag v1.2.0
echo "exit $?"
```

Expected: `REPRODUCED <H120> https://github.com/<org>/matrix-hello@v1.2.0`, `exit 0`.

## 3. Scene 2: SolarWinds (`v1.2.1`, builder3 injects a backdoor)

```bash
docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builder3
mx release --repo "$REPO" --tag v1.2.1 --commit "$C121" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.1 --output hello
echo "exit $?"
```

Expected: `verdict AGREED <H121>`, `CERTIFIED <H121>`, `exit 0`. If builder3's
vote arrived before the CLI stopped, its row shows `<BAD121[:16]>  DISAGREE` and
the CLI warns about disagreement. Otherwise wait for propagation and use TUI Detail
(`r`, `Enter`) or `mx status <request id>` to show builder3's red `DISAGREE`;
other builders with observed honest votes show `ok`.
The TUI's verdict verifies the quorum against the signed request. A standalone `DISAGREE`
evidence item with one signed vote is **unverified** without that request and quorum.

**Save the backdoored binary now** (scene 4 needs it, and the next reset deletes it):

```bash
mkdir -p dist/evil && cp "$MATRIX_DATA/builder3/artifacts/$BACKDOOR_HASH" dist/evil/hello
sha256sum dist/evil/hello                  # = BAD121
```

Say: "The backdoored binary exists, signed by a real builder, but it never reaches 3 votes."

## 4. Scene 3: a whole laptop is hacked (builder5 + builder6 collude)

Uncomment `builder5` and `builder6` in `docker-compose.faults.yml`, comment out `builder3` again.

```bash
# reset (§1), then:
docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builder5 builder6
mx release --repo "$REPO" --tag v1.2.1 --commit "$C121" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.1 --output hello
echo "exit $?"
```

Expected: the honest hash certifies (`CERTIFIED <H121>`, `exit 0`). Once both
faulty votes propagate, TUI Detail or `mx status <request id>` shows builder5
and builder6 as `<BAD121[:16]>  DISAGREE`; their two matching fake votes remain
below the threshold of 3. They need not appear before the CLI certifies.

Say: "Laptop C is the whole fault budget, f = 2. They agree with each other and it does not matter."

## 5. Scene 4: swapped download (offline machine)

Copy `dist/evil/hello`, `dist/v1.2.1/hello.matrix.json` and `dist/v1.2.0/hello.matrix.json`
(as `old.matrix.json`) to the offline machine.

```bash
matrix verify evil/hello --cert hello.matrix.json --repo "$REPO" --tag v1.2.1; echo "exit $?"
```

Expected: `MISMATCH: file sha256 differs from the certified <H121>`, `exit 1`.

```bash
matrix verify hello --cert old.matrix.json --repo "$REPO" --tag v1.2.1; echo "exit $?"
```

Expected: `INVALID_CERT: certificate is for https://github.com/<org>/matrix-hello@v1.2.0`, `exit 2`.

Say: "Only exit 0 is success. Your CI fails closed on everything else."

## 6. Scene 5: a laptop dies mid-release (laptop D = builder7 + builder8)

```bash
# reset (§1), then in terminal 1:
mx release --repo "$REPO" --tag v1.2.0 --commit "$C120" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.0 --output hello
echo "exit $?"

# in terminal 3, a few seconds later (while the builds run):
docker compose stop builder7 builder8
```

On the tinc network: pull laptop D's cable instead of `docker compose stop`.

Expected: TUI Builders shows builder7 and builder8 `reachable no`. The release still prints
`CERTIFIED <H120>`, `exit 0`, if enough remaining builders respond. The CLI prints
all 8 builder rows, but only votes already received show `ok`; absent votes show `-`.
Bring them back afterwards: `docker compose start builder7 builder8`.

## 7. Scene 6: caught cheater (builder2 equivocates)

Uncomment `builder2` in `docker-compose.faults.yml`, comment out the others.

```bash
# reset (§1), then:
docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builder2
mx release --repo "$REPO" --tag v1.2.0 --commit "$C120" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.0 --output hello
mx evidence --since 1h
```

Expected: `CERTIFIED <H120>`, exit 0. Once both conflicting signed votes propagate,
builder2 shows `EQUIVOCATION` in TUI Detail or `mx status <request id>`.
`evidence` prints `EQUIVOCATION builder2 <id[:16]> proof-ok`; if it has not
appeared yet, repeat after the next sync round. TUI: press `e`, then `Enter`
on the row: `proof (valid):` and two signed attestations by builder2
with different results. Say: "Anyone can check this proof with the genesis public keys."

Evidence appears after the next sync round (5 s in the demo profile).

## 8. On the 4-laptop network

- Each laptop runs its two builders (HLD §5.1) with `genesis.demo.json`; see `docs/OPS.md`.
- Replace `mx` with plain `matrix --genesis genesis.demo.json` and the key path with the
  release signer's own key file (H8).
- Faults: restart the chosen builder with `matrix-node ... --allow-faults --fault <mode>`
  (same flags as in `docker-compose.faults.yml`).
- Reset: stop all 8 builders, delete each builder's `--data` directory, start them again.

## 9. Fallbacks

| Problem | Do this |
|---|---|
| tinc or venue Wi-Fi down | Run every scene on one laptop with compose (this runbook as written). |
| Build slower than expected | Increase `--wait`; the builders' timeout is `build_timeout_s` in genesis. |
| A builder is `genesis MISMATCH` | It runs an old genesis. Copy the current one and restart it. |
| TUI breaks | `mx status <request id>` prints the same per-builder table; `mx evidence` for scene 6. |
| `release` exits 3 (PENDING) | `mx status <id>` to see who is missing; check `docker compose logs builderN`. |
| `release` exits 4 | Fewer than 3 builders answered, or a wrong key/genesis. Check `docker compose ps`. |
| Scene 4 file lost | Re-run scene 2 (after a reset) and copy the backdoored artifact again. |
| No time for a reset | Skip to the next scene that uses an unused tag; say which scene was skipped. |

## 10. Exit codes on the slide

| | `release` | `verify` |
|---|---|---|
| 0 | `CERTIFIED` | `REPRODUCED` |
| 1 | | `MISMATCH` |
| 2 | `NOT_REPRODUCIBLE` | `INVALID_CERT` |
| 3 | `PENDING` at timeout | |
| 4 | error | error |
| 5 | `BUILD_FAILED` | |
