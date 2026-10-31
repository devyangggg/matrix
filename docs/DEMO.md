# Matrix demo runbook

The seven scenes from [RFC §9.2](../Matrix_RFC_001.md) (rev 5), on **4 real laptops on a phone
hotspot, one builder each**: n = 4, f = 1, every builder builds (R = 4), threshold T = 2. About
6 minutes on stage. Every command below is copy-paste. Values marked `TBD` must be filled in
before the rehearsal (X2).

> `matrix up`, address discovery and `/v1/peers` are specified in rev 5 but not implemented yet
> (backlog R1 to R5). Screen text shown for `matrix up` is indicative; the `release`, `verify`,
> `status` and `evidence` lines are the real CLI output.

| Machine | Node name | Role | Terminals |
|---|---|---|---|
| Laptop A | `laptop-a` | builder **and publisher** | T1 `matrix up`, T2 `matrix tui` (on the projector), T3 `matrix release` |
| Laptop B | `laptop-b` | builder; equivocates in scene 7 | T1 `matrix up` |
| Laptop C | `laptop-c` | builder; injects a backdoor in scene 3 | T1 `matrix up` |
| Laptop D | `laptop-d` | builder; drops off the Wi-Fi in scene 6 | T1 `matrix up` |
| Machine V | none | offline `matrix verify` (H9); hosts the imposter in scene 4 | one |

V is a spare laptop or a judge's machine. If there is none, use laptop D with its Wi-Fi off for
the verify steps (its builder rejoins within ~5 s when the Wi-Fi is back).

## 0. Before the demo

### 0.1 Once per laptop

Follow [docs/OPS.md](OPS.md) §1 to §5 on A, B, C and D: WSL2 mirrored networking, firewall rules
for UDP 7788 and TCP 7700, Docker, the pinned Go image pre-pulled, the **same** Matrix checkout
(same `network.toml`) with `pip install -e .`, and the hotspot ping check. On V: the Matrix
checkout and `pip install -e .` only (no Docker needed).

### 0.2 Values to fill in

| Name | Value |
|---|---|
| `REPO` sample repo (H3) | `https://github.com/<org>/matrix-hello` |
| `IMAGE` Go image, linux/amd64 digest (H4) | `golang@sha256:TBD` |

Both must already be in `network.toml` (`allowed_repos`, `allowed_images`) in the commit every
laptop has checked out. A different `network.toml` gives a different short code in scene 1.

Expected hashes per tag (measure in the rehearsal; the version differs per tag via ldflags, so
every tag has its own hash):

| Tag | Scene | Honest hash | Backdoored hash (`backdoor.patch`) |
|---|---|---|---|
| `v1.2.0` | 2 (happy path), 5 (old certificate) | `H120 = TBD` | |
| `v1.2.1` | 3 (SolarWinds), 5 | `H121 = TBD` | `BAD121 = TBD` |
| `v1.2.2` | 6 (laptop drops off) | `H122 = TBD` | |
| `v1.2.3` | 7 (caught cheater) | `H123 = TBD` | |
| `v1.2.4` | spare | `H124 = TBD` | `BAD124 = TBD` |
| `v1.2.5` | spare | `H125 = TBD` | `BAD125 = TBD` |
| `v0.9.0-broken` | optional extra | `BUILD_FAILED` (exit 5) | |
| `v0.9.1-norecipe` | optional extra | stays `PENDING` (exit 3) | |

### 0.3 Laptop A: the publisher's shell (T3)

The CLI signs the commit, not an annotated tag object, so resolve every tag to its commit:

```bash
cd ~/Matrix && . .venv/bin/activate
export REPO=https://github.com/<org>/matrix-hello                   # H3

# Prefer the peeled ref; use the tag ref itself only for lightweight tags.
c() {
  local ref
  ref=$(git ls-remote --exit-code "$REPO" "refs/tags/$1^{}") ||
    ref=$(git ls-remote --exit-code "$REPO" "refs/tags/$1") || return 1
  printf '%s\n' "${ref%%[[:space:]]*}"
}
cat > ~/demo.env <<EOF
export REPO=$REPO
export C120=$(c v1.2.0) C121=$(c v1.2.1) C122=$(c v1.2.2) C123=$(c v1.2.3)
export C124=$(c v1.2.4) C125=$(c v1.2.5)
export KEY=\$HOME/.matrix/keys/release.key
export USB=/mnt/e                                  # the USB stick as seen from WSL
EOF
. ~/demo.env && env | grep '^C12'                  # six 40-hex SHAs, else stop and fix the repo
```

`--key` defaults to `~/.matrix/keys/release.key`; the commands pass it explicitly anyway.

### 0.4 All four laptops: start from a fresh network

Scene 1 founds the network live. A rehearsal leaves a genesis and a database behind, and later
runs of `matrix up` would skip the ceremony. Request IDs do not depend on genesis, so an old
database would also treat this demo's tags as already done. Move both aside (keys stay):

```bash
b=~/matrix-rehearsal-$(date +%Y%m%d-%H%M%S) && mkdir -p "$b"
mv ~/.matrix/genesis.json ~/.matrix/genesis.sha256 ~/.matrix/endorsements.json ~/.matrix/data "$b"/ 2>/dev/null
ls ~/.matrix                                       # only keys/ (or nothing) remains
```

Join the hotspot, check that every laptop pings every other one ([OPS.md §5](OPS.md)), and check
Wi-Fi is **off** on V.

## 1. The scenes

### Reset between scenes

Each scene uses its own tag, so nothing has to be deleted. A reset only returns the faulty
laptop to honest. On that laptop, in T1:

```bash
# Ctrl-C stops the node
matrix up                                          # genesis exists: no ceremony, no fault flags
```

The TUI on A shows the laptop online again within ~5 s. **Never more than one faulty builder at
a time** (f = 1).

### 1.1 Scene 1: zero-config founding

On **each** laptop, T1 (use its own name):

```bash
cd ~/Matrix && . .venv/bin/activate
matrix up --name laptop-a                          # laptop-b, laptop-c, laptop-d on the others
```

What judges see: each screen fills with the founders as they appear (no IPs typed, no files
edited). Expected, roughly:

```
founding network matrix-demo (network.toml params a41c…)
  laptop-a   9f3e 21c0   (you)
  laptop-b   0c7d 88a1
  laptop-c   e2b4 5f19
  laptop-d   41aa 0d3e
4 founders, params match. Press Enter to seal.
```

When all four rows are listed on every screen, each user presses **Enter**. Every laptop builds
the same genesis and shows the same short code:

```
short code 3F2A-9C1D-77E0-41B8
Read it aloud. Same on every laptop? [y/N]
```

One person reads the code aloud; each user checks their own screen and types `y`. After all four
endorsements:

```
endorsed by 4/4
wrote ~/.matrix/genesis.json, ~/.matrix/genesis.sha256, ~/.matrix/endorsements.json
node laptop-a listening on 0.0.0.0:7700, discovery on UDP 7788
```

Laptop A, T2:

```bash
cd ~/Matrix && . .venv/bin/activate && matrix tui  # b builders, r releases, Enter detail, l log, e evidence, q quit
```

The intro (about two seconds, any key skips it) hands over to the dashboard. Builders screen:
4 rows `laptop-a` to `laptop-d`, all **online**, each with its hotspot address (for example
`172.20.10.3:7700` on an iPhone hotspot), last seen under 5 s, genesis match.

Then give V the pin. On A: `cp ~/.matrix/genesis.json ~/.matrix/genesis.sha256 "$USB"/`. On V:

```bash
mkdir -p ~/.matrix && cp "$USB"/genesis.json "$USB"/genesis.sha256 ~/.matrix/
cut -c1-16 ~/.matrix/genesis.sha256                # = the short code read aloud, without dashes
export REPO=https://github.com/<org>/matrix-hello  # from the consumer, never from a certificate
```

Say: "No config, no admin: each laptop signed for itself, and we compared one code out loud."

### 1.2 Scene 2: happy path (`v1.2.0`)

Laptop A, T3:

```bash
. ~/demo.env
matrix release --repo "$REPO" --tag v1.2.0 --commit "$C120" \
  --key "$KEY" --wait 600 --out dist/v1.2.0 --output hello
echo "exit $?"
```

Expected (row order and how many votes arrived before the CLI stopped vary; unreported rows
show `-`):

```
request <64 hex> https://github.com/<org>/matrix-hello@v1.2.0
request <64 hex>
verdict AGREED <H120>
  laptop-c     laptop-c   <H120[:16]>      ok
  laptop-a     laptop-a   <H120[:16]>      ok
  laptop-d     laptop-d   -
  laptop-b     laptop-b   -
CERTIFIED <H120> -> dist/v1.2.0/hello
exit 0
```

TUI Releases (`r`): quorum `2/2`, verdict `AGREED`; attestations keep filling to `4/4` as the
other laptops finish. Copy the result for V: `cp -r dist/v1.2.0 "$USB"/`.

On V, **Wi-Fi off** (show it):

```bash
matrix verify "$USB"/v1.2.0/hello --cert "$USB"/v1.2.0/hello.matrix.json --repo "$REPO" --tag v1.2.0
echo "exit $?"
```

Expected: `REPRODUCED <H120> https://github.com/<org>/matrix-hello@v1.2.0`, `exit 0`.

Say: "Four independent laptops built the same bytes; two matching signatures make a certificate
that anyone can check with no network at all."

### 1.3 Scene 3: SolarWinds (`v1.2.1`, laptop C injects a backdoor)

Laptop C, T1:

```bash
# Ctrl-C, then:
matrix up --allow-faults --fault inject --patch examples/faults/backdoor.patch
```

Wait for `laptop-c` online in the TUI. Laptop A, T3:

```bash
matrix release --repo "$REPO" --tag v1.2.1 --commit "$C121" \
  --key "$KEY" --wait 600 --out dist/v1.2.1 --output hello
echo "exit $?"
```

Expected: `verdict AGREED <H121>`, `CERTIFIED <H121> -> dist/v1.2.1/hello`, `exit 0`. If laptop
C's vote arrived before the CLI stopped, its row reads `<BAD121[:16]>  DISAGREE` and the CLI
prints `WARNING: some builders disagree with the certified hash (reproducibility)`. Otherwise
show it in TUI Detail (`r`, `Enter`: laptop C in red, `DISAGREE`) or with
`matrix status <request id>`. Copy the result: `cp -r dist/v1.2.1 "$USB"/`.

Laptop C, save the backdoored binary for scene 5 (it really was built and signed). Move the USB
stick to laptop C first; `USB` was only set on laptop A in §0.3, so set it here too:

```bash
export USB=/mnt/e                                  # the USB stick as seen from WSL on laptop C
cp ~/.matrix/data/artifacts/<BAD121> "$USB"/evil-hello   # full hash; ls ~/.matrix/data/artifacts/<BAD121[:16]>* finds it
sha256sum "$USB"/evil-hello                              # = BAD121
```

Reset laptop C (Ctrl-C, `matrix up`).

Say: "Laptop C is hacked and signed a backdoored binary for real, but it stands alone and never
reaches two votes. With f = 1, one hacked laptop is our whole fault budget: two colluding
laptops would reach the threshold, which is exactly the bound we promise."

### 1.4 Scene 4: imposter on the hotspot

On V, **Wi-Fi on** (join the hotspot), start a rogue with a fresh key that claims to be laptop B:

```bash
matrix up --home /tmp/rogue --name laptop-b
```

What judges see: the rogue's screen finds no network to join. The founded laptops ignore
ceremony messages, so it lists only itself and can never seal (fewer than 4 founders). Its key
is not in genesis, so anything it sends as `laptop-b` fails the membership or signature check and
is dropped. TUI on A, Builders: still exactly 4 rows, `laptop-b` online at its **real** address.

Stop the rogue (Ctrl-C), `rm -rf /tmp/rogue`, and switch V's **Wi-Fi off** again.

Say: "Anyone can join the Wi-Fi; only the four keys in the genesis we all confirmed can speak for
the network."

### 1.5 Scene 5: swapped download (V, offline)

```bash
matrix verify "$USB"/evil-hello --cert "$USB"/v1.2.1/hello.matrix.json --repo "$REPO" --tag v1.2.1
echo "exit $?"
```

Expected: `MISMATCH: file sha256 differs from the certified <H121>`, `exit 1`.

```bash
matrix verify "$USB"/v1.2.1/hello --cert "$USB"/v1.2.0/hello.matrix.json --repo "$REPO" --tag v1.2.1
echo "exit $?"
```

Expected: `INVALID_CERT: certificate is for https://github.com/<org>/matrix-hello@v1.2.0`, `exit 2`.

Say: "Only exit 0 is success. A swapped binary or an old certificate fails closed in your CI."

### 1.6 Scene 6: a laptop drops off (`v1.2.2`, laptop D)

Laptop A, T3:

```bash
matrix release --repo "$REPO" --tag v1.2.2 --commit "$C122" \
  --key "$KEY" --wait 600 --out dist/v1.2.2 --output hello
echo "exit $?"
```

A few seconds later, while the builds run: **switch off laptop D's Wi-Fi.**

What judges see: after ~15 s the TUI shows `laptop-d` **offline**. The release still prints
`CERTIFIED <H122> -> dist/v1.2.2/hello`, `exit 0`, from the 3 laptops left (2 matching votes are
enough); laptop D's row shows `-`.

Switch laptop D's Wi-Fi back on. Within ~5 s it is **online** again, often with a new DHCP
address. It catches up by pull sync: it learns the request is settled and does not build it, or
re-sends the vote it already stored. `matrix status <request id>` on A shows its row once its
vote has arrived.

Say: "Offline is not leaving. A missing laptop can delay a release, never mislead it, and it
catches up the moment it is back."

### 1.7 Scene 7: caught cheater (`v1.2.3`, laptop B equivocates)

Laptop B, T1:

```bash
# Ctrl-C, then:
matrix up --allow-faults --fault equivocate
```

Wait for `laptop-b` online. Laptop A, T3:

```bash
matrix release --repo "$REPO" --tag v1.2.3 --commit "$C123" \
  --key "$KEY" --wait 600 --out dist/v1.2.3 --output hello
matrix evidence --since 1h
```

Expected: `CERTIFIED <H123> -> dist/v1.2.3/hello` (laptops A, C and D are honest). Once both
conflicting votes have propagated, laptop B's row reads `-  EQUIVOCATION`, and `evidence` prints:

```
EQUIVOCATION laptop-b     <request id[:16]> proof-ok
```

If it prints `no evidence`, repeat after the next sync round (5 s in the demo profile). TUI: press
`e`, then `Enter` on the row: `proof (valid):` and two attestations signed by laptop B with
different results.

Reset laptop B (Ctrl-C, `matrix up`).

Say: "Lying twice leaves a signed confession. Anyone can check this proof with the genesis public
keys."

### Optional extras (time permitting)

`v0.9.0-broken`: every builder confirms the compile error, `BUILD_FAILED`, exit 5.
`v0.9.1-norecipe`: every builder abstains (`BAD_RECIPE`), stays `PENDING`, exit 3 (use `--wait 60`).
Commits: `c v0.9.0-broken`, `c v0.9.1-norecipe` (§0.3).

## 2. Fallbacks

| Problem | Do this |
|---|---|
| Founders do not appear in `matrix up` | Broadcast is blocked. Check the firewall rules and WSL mirrored mode ([OPS.md §2](OPS.md)), then client isolation (ping, OPS §5). Ctrl-C and run `matrix up` again; nothing is written before all four endorse. |
| An extra or unknown founder row | Do **not** seal. Find the device (rogue or a stale process), stop it, Ctrl-C and restart `matrix up` on all four. |
| Short codes differ | Never type `y`. Different founders were seen, or `network.toml` differs: compare `git rev-parse HEAD` and `sha256sum network.toml`, fix, restart `matrix up` on all four. Without all four `y`, it aborts after 5 minutes and writes nothing. |
| A builder shows offline | Its hellos do not arrive: firewall (UDP 7788), Wi-Fi, or the node stopped. Check T1 on that laptop; restart `matrix up`. One offline builder still certifies. |
| Hotspot isolates clients (no ping) | Switch to the backup hotspot or travel router checked in [OPS.md §5](OPS.md). Re-check ping. No re-founding needed: addresses are not in genesis. |
| A laptop dies for real | Carry on: with 3 honest builders every scene still certifies. If it was a scene's faulty laptop, skip that scene (say why); never make a second laptop faulty. |
| Ceremony cannot complete at all | Restore the rehearsal network on all four (`mv` the files from `~/matrix-rehearsal-*` back into `~/.matrix/`, then `matrix up`). Tags released in the rehearsal return their stored result; use the spare tags. |
| TUI breaks | `matrix status <request id>` prints the same per-builder table; `matrix evidence --since 1h` for scene 7. |
| `release` exits 3 (`PENDING`) | `matrix status <id>` to see who is missing; check T1 on those laptops. Increase `--wait` if builds are slow (`build_timeout_s` is in `network.toml`). |
| `release` exits 4 | Fewer than 2 builders answered, the local node is not running (T1), or a wrong key or genesis. |
| A scene must be repeated | A tag cannot be released twice (same request ID, same stored result): use the spare tags `v1.2.4`, `v1.2.5` with `C124`, `C125`. A repeated scene 3 changes the backdoored hash (`BAD124`) and the tag in scene 5. |
| Scene 5 file lost | Copy it again from laptop C: `~/.matrix/data/artifacts/<BAD121>` (artifacts expire after 24 h). |
| Hotspot or all networking fails | Last resort: run every scene on one machine with the compose dev network ([Appendix](#appendix-single-machine-rehearsal)). |

## 3. Exit codes on the slide

| | `release` | `verify` | `status` |
|---|---|---|---|
| 0 | `CERTIFIED` | `REPRODUCED` | settled |
| 1 | | `MISMATCH` | |
| 2 | `NOT_REPRODUCIBLE` | `INVALID_CERT` | |
| 3 | `PENDING` at timeout | | `PENDING` |
| 4 | error | error | error |
| 5 | `BUILD_FAILED` | | |

## Appendix: single-machine rehearsal

The development network: 8 builders in Docker Compose on one Linux or WSL2 machine, static `addr`s
from `scripts/dev_genesis.py`, no ceremony and no discovery (n = 8, f = 2, T = 3, so votes and
quorum counts differ from the laptop demo).

```bash
cp .env.example .env                       # set MATRIX_DATA (absolute), MATRIX_UID/GID, DOCKER_GID
. ./.env && mkdir -p "$MATRIX_DATA" dist
export REPO=https://github.com/<org>/matrix-hello IMAGE=golang@sha256:TBD
python scripts/dev_genesis.py --out dev --addrs compose --profile demo --repo "$REPO" --image "$IMAGE"
docker pull --platform linux/amd64 "$IMAGE"
docker compose build && docker compose up -d && docker compose ps   # 8 x healthy
alias mx='docker compose run --rm cli'
mx tui                                     # second terminal
```

Use `c()` from §0.3 for the commits. Then run the scenes with `mx` instead of `matrix`:

```bash
mx release --repo "$REPO" --tag v1.2.0 --commit "$C120" \
  --key /etc/matrix/keys/release.key --wait 600 --out dist/v1.2.0 --output hello
```

| Laptop scene | Compose equivalent |
|---|---|
| 1 founding, 4 imposter | Not applicable (static dev genesis). |
| 3 SolarWinds | `docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builder3`; the backdoored file is `$MATRIX_DATA/builder3/artifacts/<BAD121>`. |
| 5 swapped download | `matrix verify` with `--genesis dev/genesis.json --genesis-sha256 "$(cat dev/genesis.sha256)"`. |
| 6 drop off | `docker compose stop builder7 builder8`, later `docker compose start builder7 builder8`. |
| 7 cheater | Uncomment `builder2` in `docker-compose.faults.yml`, comment out the others, `up -d builder2`. |
| reset | `docker compose up -d builderN` (honest again), or wipe everything: `docker compose down && sudo rm -rf "$MATRIX_DATA"/builder* && docker compose up -d`. |

## Pitch for the judges

"Finding each other is automatic; deciding who counts is not. In a system that tolerates attackers,
letting the network decide who counts is exactly the attack."

"There's no admin key anywhere. The network exists only because every founding laptop signed the
same constitution, and every certificate is tied to it."
