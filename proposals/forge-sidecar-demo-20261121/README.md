# forge sidecar — credential-monopoly demo (Docker, container-tier) 2026-11-21

A **working, validated** slice of Forge's Phase-1 enforcement: a runaway / prompt-injected agent that
**physically cannot** leak the secret, bypass the airlock, or overspend — and the overspend is refused by the
**actual compiled proved verifier**, not a reimplementation. Run it:

```sh
docker compose up --build --abort-on-container-exit --exit-code-from agent
```

## What it shows (actual output, reproduced on Docker 28.5.1)
```
[agent] can I see STRIPE_KEY in my env? -> False     (credential monopoly)
[agent] call Stripe DIRECTLY: BLOCKED (gaierror)     (network isolation)
[agent] reach the internet:   BLOCKED (OSError)      (no egress)
[agent] charge #1 $20 -> ACCEPT          gross=$20/$50
[agent] charge #2 $20 -> ACCEPT          gross=$40/$50
[agent] charge #3 $20 -> REJECT_OVER_CAP gross=$40/$50
the over-cap charges never reached Stripe.
```
- The agent container has **no `STRIPE_KEY`** (scrubbed) and sits on an **`internal: true`** (no-egress)
  network — it cannot reach the mock Stripe or the internet; it can only talk to the sidecar.
- The sidecar holds the single secret and, on every request, **appends a real 128-byte escrow record to a
  `.bin` WAL and runs the compiled proved Leg-1 Dafny verifier** (`sidecar/build/escrow-py`, via
  `leg1_cli.py`) on it. The API key is used **only** if the verifier returns `ACCEPT`. The runaway loop is
  `ACCEPT`ed to the cap, then `REJECT_OVER_CAP` — by the proof's own verdict.
- The agent's first two steps are a **breach canary**: it tries to read the key and reach Stripe/internet
  directly and reports each as BLOCKED; if any succeeded, isolation would have failed loudly.

## The gate is the proved core — no asterisk
The `ACCEPT`/`REJECT_OVER_CAP` decision is produced by the **compiled Dafny verifier whose `0 <= gross <= cap`
and conservation properties are formally proved** (`proposals/escrow-dual-leg-20261121/`, 86 obligations; the
same invariant whose proof killed mutant M10). The sidecar only *encodes* each spend into the WAL (a
128-byte layout validated byte-for-byte) and *forwards* the key on `ACCEPT`; the money decision itself is the
proved verifier's.

## Honest labels (still true)
- **Container-tier, not hardware-tier.** Containers share the host kernel — real against prompt injection, a
  buggy/chaotic agent, and shell-bypass; a container-escape kernel 0-day needs a microVM (`--vm`, a later tier).
- **The WAL encoder and the I/O glue are NOT proved** (NATIVE CHECK). What's proved is the *verdict logic* the
  gate runs. A bug in the encoder would be caught by the verifier rejecting a malformed record, not by a proof
  of the encoder.
- **Mock Stripe, no real money.** `end_to_end=false`: this is ONE link (the effect door + credential monopoly,
  container-tier), not a deployed system. The microVM tier, hardware human cosign (S1), and the independent
  security audit are still ahead.

## Files
`docker-compose.yml` (two networks: `internal` no-egress for the agent, `egress` for the sidecar↔Stripe),
`sidecar/` (Dockerfile + `sidecar.py` + the compiled proved verifier under `build/escrow-py` + `leg1_cli.py` +
pinned `a.pub`/`b.pub` + manifest), `agent.py` (runaway + breach canary), `stripe_mock.py` (charges only with
the correct key).
