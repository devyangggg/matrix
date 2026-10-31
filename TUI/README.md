# Matrix TUI

A read-only Textual view of a running Matrix network (RFC §7.12, LLD §3.14). The code is
`matrix/tui.py`, part of the root package: one CLI, one envelope parser, one `verdict()`.

## Launch

From the repository root, with `pip install -e ".[dev]"` done:

```bash
matrix --genesis /path/to/trusted/genesis.json tui --node builder1
```

`--genesis` goes **before** `tui` (default: `$MATRIX_GENESIS`, else `~/.matrix/genesis.json`).
`--node` is the builder to poll (default: the first one in genesis). Get the genesis from a
trusted channel, never from a builder: node addresses and public keys come from that file.

## Screens

| Key | View | Contents |
|---|---|---|
| `b` | Builders | Operator, builder, address, reachable, genesis-hash match, clock |
| `r` | Releases | Request ID, `repo@tag`, phase, attested x/R, quorum x/T, verdict |
| `Enter` on a release | Detail | Per builder: result, whether it matches the quorum |
| `l` in Detail | Log | Toggles the chosen builder's `/v1/requests/{id}/log` tail |
| `e` | Evidence | Kind, signer, release, time. `Enter` shows the proof JSON and whether it verifies |
| `q` | Quit | |

## Behaviour

- Polls the chosen builder's requests, bundles and evidence every second, and every genesis
  builder's `/v1/health`. Polls never overlap, so a slow builder cannot stack them up.
- Keeps only the last poll result. It reads no database, signs nothing and submits nothing.
- Shows at most 20 releases, newest first.

## Trust boundary

- Each request is re-validated locally: its release signature must be valid and its content
  hash must equal the ID the builder listed, otherwise it is shown as invalid. A bundle can
  never substitute its own request.
- The verdict is computed locally by `verdict()` from signed attestations. `AGREED` means a
  verified quorum, **not** that an artifact was downloaded and hash-checked.
- Evidence proofs are checked locally (`valid` or `NOT a valid proof`): equivocation needs two
  signed, conflicting attestations from the named signer for that request. `STALL` has no proof.
- Health, phase and log text are unsigned claims from the builder. Remote text is rendered
  literally, not as Rich markup.

## Tests

```bash
pytest -q tests/test_tui.py
```
