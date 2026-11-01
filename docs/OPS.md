# Matrix operations runbook

Per-laptop setup and the founding ceremony for the rev 5 network: **4 laptops on one LAN (a phone
hotspot), one builder per laptop**, n = 4, f = 1, threshold T = 2. Each laptop is its own
operator. Do §1 to §5 once per laptop, then found the network together (§6). The demo itself is in
[DEMO.md](DEMO.md).

> Run `matrix` itself natively on every laptop (WSL2 on Windows, directly on Linux and macOS),
> never in a container: on Docker Desktop a container's network is Docker's own VM
> (`192.168.65.x`), so its broadcasts never reach the hotspot and its advertised address is
> unreachable. Docker only runs the sandboxed Go builds. Screen text below is approximate.

## 1. What every laptop needs

| Item | Value |
|---|---|
| OS | Linux (e.g. Debian), macOS (Apple Silicon too, §3.1), or Windows 11 with **WSL2** (run Python, Docker and `matrix` from WSL2, never PowerShell) |
| Python | nothing to install: [uv](https://docs.astral.sh/uv/) fetches Python 3.11 (`.python-version`) |
| Docker | Docker Engine (Linux, and inside WSL2) with gVisor, or Docker Desktop on macOS (§4). It only runs the builds |
| Inbound ports | **UDP 7788** (discovery hellos and ceremony), **TCP 7700** (builder API) |
| Matrix | the **same commit** of this repo on every laptop (same `network.toml`) |
| Go image | the pinned `golang@sha256:<digest>` (AGENTS H4); `matrix up` pulls it if missing |

## 2. Windows: WSL2 mirrored networking and firewall

Mirrored networking gives WSL2 the laptop's own Wi-Fi address, so broadcasts and inbound
connections reach the builder. Needs Windows 11 22H2+ and WSL 2.0+ (`wsl --version`).

Create or edit `%UserProfile%\.wslconfig` (keep any other lines you already have):

```ini
[wsl2]
networkingMode=mirrored
```

Then, in **admin PowerShell**:

```powershell
wsl --shutdown

# Hyper-V firewall (in front of WSL): block everything by default, then open only Matrix's two
# ports. Never set DefaultInboundAction Allow: it would expose every other service running in WSL
# to the whole hotspot.
$wsl = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'   # the WSL VM creator id
Set-NetFirewallHyperVVMSetting -Name $wsl -DefaultInboundAction Block
New-NetFirewallHyperVRule -Name MatrixDiscovery -DisplayName "Matrix discovery (UDP 7788)" -Direction Inbound -VMCreatorId $wsl -Protocol UDP -LocalPorts 7788 -Action Allow
New-NetFirewallHyperVRule -Name MatrixApi -DisplayName "Matrix builder API (TCP 7700)" -Direction Inbound -VMCreatorId $wsl -Protocol TCP -LocalPorts 7700 -Action Allow

# Windows Defender Firewall: Matrix ports on the hotspot (private) profile
New-NetFirewallRule -DisplayName "Matrix discovery (UDP 7788)" -Direction Inbound -Protocol UDP -LocalPort 7788 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "Matrix builder API (TCP 7700)" -Direction Inbound -Protocol TCP -LocalPort 7700 -Action Allow -Profile Private
# Lets the other laptops ping this one for the §5 check (Windows drops ping by default)
New-NetFirewallRule -DisplayName "Matrix ping check (ICMPv4)" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Private

# After joining the hotspot: it must be Private, or the rules above do not apply
Get-NetConnectionProfile
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
```

Check inside WSL: `ip -4 addr` shows the same Wi-Fi address as `ipconfig` on Windows. If WSL shows
a `172.x` NAT address instead, mirrored mode is not active (check the file name and run
`wsl --shutdown` again).

## 3. Linux laptops

No WSL step. If a firewall is active, open the same ports:

```bash
sudo ufw allow 7788/udp && sudo ufw allow 7700/tcp                      # ufw
sudo firewall-cmd --add-port=7788/udp --add-port=7700/tcp               # firewalld (until reboot)
```

Docker Engine and gVisor: §4.

### 3.1 macOS laptops (Apple Silicon included)

No WSL step; run everything in Terminal.

- Docker Desktop, with **Settings > General > Use Rosetta for x86_64/amd64 emulation on Apple
  Silicon** on. The pinned Go image is `linux/amd64`, so on Apple Silicon every build runs
  emulated: slower, but it must give the same hash. Check both in the rehearsal: the Mac's
  `v1.2.0` vote must equal `H120` ([DEMO.md §0.2](DEMO.md)), and its build time must fit
  `build_timeout_s` in `network.toml` (raise it there, in the shared commit, before founding).
- Firewall: the first `matrix up` triggers "Accept incoming network connections?" for Python:
  click **Allow** (or turn the firewall off for the demo in System Settings > Network > Firewall).
- Differences in the commands: this laptop's address is `ipconfig getifaddr en0` (not
  `ip -4 addr`), `sha256sum` is `shasum -a 256`, and a USB stick is under `/Volumes/<name>`.

## 4. Docker, gVisor and the Matrix checkout

Docker only runs the builds; `matrix` itself runs natively (the note at the top). Builds run with
every sandbox flag (no network while compiling, no capabilities, non-root, read-only source,
limits) and, wherever Docker has it, on **gVisor**: a user-space kernel, so a hostile build never
reaches the kernel of the laptop that holds the keys. Builds under gVisor give the same hashes.

| Laptop | Docker | Kernel isolation of builds |
|---|---|---|
| Linux (Debian) | Docker Engine | gVisor (§4.1) |
| Windows | Docker Engine **inside WSL2** (§4.1). Docker Desktop cannot load gVisor: turn off its WSL integration for this distro, or quit it | gVisor (§4.1) |
| macOS | Docker Desktop | its own Linux VM (gVisor is Linux-only); nothing to do |

`matrix up` prints which one is active (`build isolation: ...`) and warns if builds would share
this laptop's kernel.

Docker Engine on Debian or WSL2 Ubuntu (WSL2 needs `systemd=true` under `[boot]` in
`/etc/wsl.conf`, the default on new installs):

```bash
sudo apt install -y docker.io && sudo usermod -aG docker $USER   # then log out and in again
docker run --rm hello-world                                       # works without sudo
```

### 4.1 gVisor (Linux and WSL2)

From [gvisor.dev](https://gvisor.dev/docs/user_guide/install/); the package registers the `runsc`
runtime with Docker:

```bash
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc
sudo systemctl restart docker
docker run --rm --runtime=runsc hello-world                       # works: gVisor is ready
```

### 4.2 The Matrix checkout

Install [uv](https://docs.astral.sh/uv/) once (`curl -LsSf https://astral.sh/uv/install.sh | sh`,
or `brew install uv` on macOS). Then, in the home directory (on Windows the WSL2 home, not under
`/mnt/c`: key file modes and speed):

```bash
git clone https://github.com/ChaoticNebula5/Matrix ~/Matrix && cd ~/Matrix
uv sync                                     # Python 3.11 and every dependency, in .venv
. .venv/bin/activate                        # or prefix every command with `uv run`
matrix help
git rev-parse HEAD && sha256sum network.toml   # compare on all four laptops
```

The first `matrix up` checks Docker and pulls the pinned Go image if it is missing (about 800 MB:
do it once before the venue, not on the hotspot).

`network.toml` holds the network parameters every founder must agree on. It is checked into the
repo, so the same checkout means the same values. For the demo it is (H3 and H4 filled in; pull the
same commit on every laptop):

```toml
[network]
name = "matrix-demo"
allowed_repos = ["https://github.com/ChaoticNebula5/matrix-hello"]
allowed_images = { "go1.23" = "golang@sha256:e87b2a5f6df2dff71ea330d55d54f4979eb380ae58a7e3aabc9d53121243e689" }
allowed_goos = ["linux"]
allowed_goarch = ["amd64"]
build_timeout_s = 45
request_ttl_s = 3600
sync_interval_s = 5
```

## 5. Hotspot check (before every venue)

Some hotspots isolate clients from each other; Matrix then cannot work. An iPhone hotspot uses a
/28 subnet (`172.20.10.0/28`: the phone plus up to 13 clients, enough for 4 laptops). Join the
hotspot on all four laptops, then in WSL2:

```bash
ip -4 addr                                  # note this laptop's address
ping -c 3 <other laptop's address>          # from every laptop to every other one
```

Broadcast check (UDP 7788; run before `matrix up`, while the port is free). Listener on one
laptop, sender on another:

```bash
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('',7788));print(s.recvfrom(512))"
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.sendto(b'hi',('255.255.255.255',7788))"
```

The listener prints `(b'hi', ('<sender address>', <port>))`. If ping or the broadcast fails although
both laptops have an address on the hotspot, the hotspot isolates clients (or a firewall blocks):
fix the firewall (§2, §3), turn off any "AP isolation" setting on the phone, or switch to the
backup (a second phone's hotspot or a travel router, checked the same way in advance).

## 6. Founding ceremony: `matrix up`

One command per laptop, no files to edit, no authority. All four laptops, at the same time:

```bash
cd ~/Matrix && . .venv/bin/activate
matrix up --name laptop-a                   # laptop-b, laptop-c, laptop-d on the others
```

`--name` defaults to the hostname (lowercased, invalid characters replaced by `-`, at most 24
characters); it must match `[A-Za-z0-9_-]{1,24}` and be unique in the network.

What happens:

1. **Keys.** `~/.matrix/keys/node.key` and `~/.matrix/keys/release.key` are generated if absent
   (64 hex seed, mode 0600). They never leave the laptop.
2. **Founders.** Every laptop announces itself on UDP 7788 every 2 s (name, public keys, hash of
   the `network.toml` values, self-signed). The screen lists founders as they appear, with a short
   key fingerprint, and flags any founder whose parameters differ from ours:

   ```
   founding network matrix-demo (network.toml params a41c…)
     laptop-a   9f3e 21c0   (you)
     laptop-b   0c7d 88a1
     laptop-c   e2b4 5f19
     laptop-d   41aa 0d3e
   4 founders, params match. Press Enter to seal.
   ```

3. **Propose.** When the expected laptops are listed, **one** user presses **Enter**. That laptop
   builds the genesis from the founders it has heard (nodes and release signers sorted by public
   key, no addresses, f = n // 4, replicas = n, threshold = f + 1), shows its **short code** (the
   first 16 hex characters of the genesis hash) and sends a signed **proposal** carrying the list
   of founders (name and key) and the hash. Proposals are refused with fewer than 2 founders,
   duplicate names, a key announced under two names, or any parameter mismatch. With 2 or 3
   founders f = 0: one builder alone certifies, so use them for testing only; the demo needs 4.

   ```
   Proposing to seal 4 founders: ...
   Short code: 3F2A-9C1D-77E0-41B8
   The others are asked to accept it. Read the short code aloud. Confirm? [y/N]
   ```

4. **Accept.** Every other laptop prints the proposal: who proposes, the short code, the founder
   list, and what differs from what it has heard itself (a founder not heard yet, a founder the
   proposal lacks, a different name, a different `network.toml`):

   ```
   >> laptop-a (9f3e21c0) proposes to seal 4 founders, short code 3F2A-9C1D-77E0-41B8:
        laptop-a ...
      Same list as yours. Type y to accept once the short code matches aloud.
   ```

   A proposal that arrives before a founder it lists is not lost: the screen says what is not heard
   yet and shows the proposal again as soon as everything matches. The proposer re-sends it every
   2 s with its announcement, so lost packets only delay. **Type `y` only if the short code read
   aloud matches and the list is exactly the expected laptops.** This human comparison is the
   trust root (like Bluetooth pairing or Signal safety numbers). A proposer can answer `n` to
   withdraw; `y` at the main prompt accepts another laptop's proposal instead. If a proposal says
   "Cannot accept this" (you also hear a founder it lacks), press Enter to propose the full list.
5. **Endorse.** Each laptop that confirmed broadcasts a signed endorsement of the genesis hash. Genesis
   becomes active only with a valid endorsement from **every** node in it: anyone can veto. After 5
   minutes without all endorsements the ceremony aborts and nothing is written.
6. **Run.** On success it writes `~/.matrix/genesis.json`, `~/.matrix/genesis.sha256` and
   `~/.matrix/endorsements.json`, then starts the node in the same process: listen
   `0.0.0.0:7700`, data `~/.matrix/data`, discovery on UDP 7788. On a terminal, a fresh founding
   then opens the dashboard (`matrix tui`) in the same window once the builder answers; `q`
   closes it and the builder keeps running (Ctrl-C stops it). With `-v` the log goes to
   `~/.matrix/verbose.log` while the dashboard is open. Later runs of `matrix up` do not open it:
   run `matrix tui` in a second terminal.

On a mismatch, **never type `y`**:

| You see | Cause | Do this |
|---|---|---|
| An extra or unknown founder row | A rogue device or a stale `matrix up` on the hotspot | Do not seal. Find and stop it; Ctrl-C and restart `matrix up` on all laptops. |
| A founder flagged for params | Its `network.toml` differs | Compare `git rev-parse HEAD` and `sha256sum network.toml`; check out the same commit; restart. |
| Short codes differ | Laptops saw different founders, or different `network.toml` | Compare the founder lists row by row; fix; restart `matrix up` on all laptops. |
| A laptop missing from the list | Its announcements do not arrive | §12 "Founders not appearing". |

Later runs of `matrix up` find `~/.matrix/genesis.json` and skip the ceremony.

## 7. Files under `~/.matrix/`

| Path | What | Share? |
|---|---|---|
| `keys/node.key` | builder signing key (64 hex seed, 0600) | **Never.** It stays on this laptop. |
| `keys/release.key` | this laptop's release-signer key (`<name>-rel` in genesis) | **Never.** |
| `genesis.json` | the network constitution: members, public keys, parameters | Public |
| `genesis.sha256` | the genesis hash, the pin | Public, through a trusted channel (§9) |
| `endorsements.json` | every founder's signed endorsement of the genesis hash | Public |
| `data/matrix.db` | SQLite: requests, attestations, build queue, evidence | Local |
| `data/logs/`, `data/artifacts/`, `data/work/` | build logs, built binaries (kept 24 h), build scratch | Local; logs are served to loopback only |

Private keys never leave the laptop that generated them; only public keys go into genesis. A lost
key means that laptop can no longer vote or release; re-found (§10).

## 8. Running the node

```bash
matrix up                                   # start (no ceremony once genesis exists); Ctrl-C stops
curl -s http://127.0.0.1:7700/v1/health     # genesis hash and node id
curl -s http://127.0.0.1:7700/v1/peers      # latest verified hello per member (untrusted, re-verified by clients)
```

- A node is **online** while its last hello is under 15 s old; hellos go out every 5 s and on
  any address change. The address book is in memory and refills within 5 s after a restart.
- Disconnect is not leave: an offline laptop stays a member and catches up when it is back (pull
  sync, re-sending its own stored votes; it never rebuilds a voted or settled request).
- `--advertise HOST:PORT` overrides the advertised address (default: this laptop's LAN address
  with port 7700).
- Demo faults: `matrix up --allow-faults --fault MODE [--patch FILE] [--hash HEX]`. Inert without
  `--allow-faults`. With f = 1, never more than one faulty laptop at a time.
- `release`, `status`, `evidence` and `tui` find the builders through the local node
  (`--node`, `$MATRIX_NODE`, default `127.0.0.1:7700`), so keep `matrix up` running on the
  publisher's laptop.

## 9. Publishing the genesis pin

Consumers pin the genesis hash obtained through a trusted channel, plus a copy of `genesis.json`:

```bash
cat ~/.matrix/genesis.sha256                # 64 hex; its first 16 characters are the short code
```

Publish the hash in the project README (in the source repository, never only on the release
page: RFC A5), and `genesis.json` (and
`endorsements.json`) next to it. Consumers check them into their own repo, as in
[examples/ci/consumer.yml](../examples/ci/consumer.yml) (`matrix/genesis.json`,
`matrix/genesis.sha256`). `matrix verify` refuses a genesis file that does not match the pin.

## 10. Re-founding

Membership is fixed at founding. Adding, removing or replacing a laptop, or changing
`network.toml`, means founding a new network:

```bash
b=~/matrix-network-$(date +%Y%m%d-%H%M%S) && mkdir -p "$b"
cp ~/.matrix/genesis.json ~/.matrix/genesis.sha256 ~/.matrix/endorsements.json "$b"/   # keep the old pin
mv ~/.matrix/data "$b"/                     # request IDs do not depend on genesis: start a fresh database
matrix up --refound --name laptop-a         # the ceremony again, on every laptop of the new network
```

The new network has a new genesis hash. Certificates issued under the old one still verify
against the old pin, so consumers keep the old `genesis.json` and hash for old releases and pin
the new ones for new releases.

## 11. Optional: tinc or WireGuard

Plain LAN is the default. It loses only **confidentiality**: anyone on the hotspot can see which
releases are built and their results. Integrity comes from the signatures, so safety is the same.
For privacy, run tinc ([RFC §7.13](../Matrix_RFC_001.md)) or WireGuard between the laptops and
advertise the tunnel address:

```bash
matrix up --advertise 10.77.0.1:7700        # this laptop's tunnel address
```

Hellos are still broadcast on the LAN (they carry only a member id, an address and a signature);
builder traffic then goes over the tunnel. Restrict TCP 7700 to the tunnel interface if you want
the API off the LAN.

## 12. Troubleshooting

| Symptom | Check |
|---|---|
| Founders not appearing | Broadcast blocked: Windows firewall rules and profile `Private` (§2), Hyper-V rules `MatrixDiscovery`/`MatrixApi` missing (`Get-NetFirewallHyperVRule -VMCreatorId $wsl`), WSL not mirrored (`ip -4 addr` shows `172.x`), client isolation (§5 broadcast check). |
| Short codes differ | Different founders seen (compare lists) or different `network.toml` (compare `git rev-parse HEAD`, `sha256sum network.toml`). Restart `matrix up` on all laptops. |
| Seal refused | Fewer than 2 founders, a duplicate `--name`, a key announced under two names (a stale `matrix up` on one laptop), or a params mismatch flag. |
| Proposal says "Cannot accept this" or "waiting" | The laptops heard different founders. The screen says which: a founder not heard yet (wait, it re-checks itself), a founder the proposal lacks (press Enter on the laptop that hears everyone to propose the full list), a different name or `network.toml`. |
| Ceremony aborted after 5 min | Not every laptop typed `y`, or endorsements do not arrive (UDP 7788). Nothing was written; run `matrix up` again. |
| A builder offline in the TUI | Its hellos do not arrive: firewall (UDP 7788), Wi-Fi, or its node stopped. `curl -s http://127.0.0.1:7700/v1/peers` on another laptop shows its last hello. |
| Online but builds never arrive | TCP 7700 blocked inbound on that laptop (§2, §3), or a wrong `--advertise`. |
| `matrix: no builder accepted the request` | The local node is not running, or no peer is reachable on TCP 7700. |
| Build `ERROR` on one laptop | Docker not reachable from WSL (`docker ps`), image not pre-pulled, disk full, or no internet for `git clone` / the Go module proxy. Environmental errors abstain, they never vote. |
| `evidence --since` window looks wrong | Each builder filters on its own clock; fix large clock skew between laptops. |
| Anything unclear | Add `-v`/`--verbose` to any command (`matrix up -v`, `matrix release -v ...`): every step, UDP packet sent/received, HTTP call and Docker command is logged to stderr (`matrix tui -v` writes `~/.matrix/verbose.log`). In `matrix up -v`, each 2 s round prints `sent N, received own echo A / from others B`: `B` stays 0 when no other laptop's packets arrive (§5 broadcast check). |
