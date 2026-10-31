# Matrix observatory

The TUI is part of the root `matrix` package and implements RFC §7.12 using Textual.
The former standalone curses/demo package has been removed: there is one CLI,
one envelope parser, and one verdict implementation. No simulated data is substituted
when a builder is unavailable.

## Install and launch

Run from the repository root, not from `TUI/`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
matrix --genesis /path/to/trusted/genesis.json tui --node builder1
```

`--node` defaults to the first builder in genesis. `--genesis` may also follow `tui`;
its default is `$MATRIX_GENESIS`, otherwise `~/.matrix/genesis.json`. Obtain the
trusted genesis through an independent trusted channel, not from a builder response.
The TUI uses the node addresses and public keys from that file.

## Screens

| Key | View | Contents |
|---|---|---|
| `b` | Builders | Operator-grouped IDs, addresses, reachability, genesis-hash match, current successful health observation time |
| `r` | Releases | Request ID, repo/tag, phase, valid non-equivocating signer count, quorum progress, locally computed verdict |
| `Enter` in Releases | Detail | Selected builders' signed results, quorum matches, disagreements, excluded equivocators |
| `l` in Detail | Log tail | Toggle the chosen builder's actual `/v1/requests/{id}/log` response |
| `e` | Evidence | Kind, signer, request, timestamp; `Enter` opens the supplied proof JSON |
| `q` | Quit | Close the application and HTTP session |

The app polls the chosen builder's request, bundle, and evidence endpoints every
second and checks every genesis builder's `/v1/health`. Polls are asynchronous and
never overlap. The log is fetched only while its pane is open. Failed refreshes clear
old successful results; unavailable data is not a certification failure or success.
Only the current poll snapshot and navigation selection are retained; failed health
checks show an unavailable observation time rather than retaining a historical last-seen value.

## Trust boundary

- The request comes from `/v1/requests/{id}`. Its release signature and content-derived
  ID are checked before the root `verdict()` evaluates bundle attestations. A bundle
  cannot substitute its own request.
- Duplicate JSON fields are rejected. Only valid, selected, non-equivocating signers
  for that exact request contribute to quorum; duplicate votes do not increase it.
- `AGREED` means a verified signed quorum, **not** a downloaded and hash-verified
  release artifact or a complete certificate.
- Health (`node_id`), phase, log text, and remote evidence records remain unsigned
  observations/claims. Proof JSON is displayed, not automatically authenticated.
  Remote text is rendered literally, not as Rich markup.
- The app reads no database, signs nothing, and submits no build work.

## Backend prerequisite

A running builder implementing `docs/openapi.yaml` is required for live data. In this
checkout, the production `Store` and build runner are still unimplemented, so
`matrix-node` cannot yet start a complete builder. This integration does not conceal
that missing backend or replace it with a demo server.

The TUI integration tests exercise the real HTTP routes and protocol engine with
an isolated test-only in-memory store, signed release requests, and signed attestations.
They cover navigation, local logs, proof JSON, invalid signatures/request substitution,
late equivocation, unavailable refreshes, and polling responsiveness.

```bash
.venv/bin/python -m pytest -q
```
