# forge sidecar — credential-monopoly demo (Docker, container-tier) 2026-11-21

A **working, validated** slice of Forge's Phase-1 enforcement: a runaway / prompt-injected agent that
**physically cannot** leak the secret, bypass the airlock, or overspend. Run it:

```sh
docker compose up --abort-on-container-exit --exit-code-from agent
```

## What it shows (actual output, reproduced on Docker 28.5.1)
- The agent container has **no `STRIPE_KEY`** in its environment (scrubbed) — only the sidecar holds it.
- The agent is on an **`internal: true`** network: it **cannot** reach the mock Stripe directly (DNS/no route)
  and **cannot** reach the internet. The only thing it can talk to is the sidecar.
- The sidecar holds the single secret, enforces a **spend cap**, and forwards to Stripe *with* the key only
  when the cap allows. A runaway loop charging $20 repeatedly is `ACCEPT`ed to $40, then `REJECT_OVER_CAP`
  at the $50 cap — and the over-cap charges **never reach Stripe**.
- The agent's own first two steps are a **breach canary**: it tries to read the key and reach Stripe/internet
  directly and reports each as BLOCKED; if any succeeded, the isolation would have failed loudly.

## Honest labels (read these)
- **Container-tier, not hardware-tier.** Containers share the host kernel. This is real isolation against the
  threats that matter day-to-day — prompt injection, a buggy/chaotic agent, a shell-bypass attempt. It does NOT
  stop a container-escape kernel 0-day; that needs a microVM (`--vm`, a later tier).
- **The cap here is a faithful reimplementation, not yet the proved binary.** The sidecar enforces the *same*
  money-conservation invariant (`0 <= gross <= cap`) that IS formally proved in the escrow core
  (`proposals/escrow-dual-leg-20261121/leg1/Leg1Escrow.dfy`, the invariant whose proof killed mutant M10).
  Wiring the compiled proved verifier in as the gate is the next step; today the sidecar runs an inline check
  of that invariant.
- **Mock Stripe, no real money.** `end_to_end=false`: this demonstrates ONE link (the effect door +
  credential monopoly, container-tier), not a deployed system. The hardware-VM tier, the hardware human
  cosign (S1), and the independent security audit are still ahead.

## Files
`docker-compose.yml` (two networks: `internal` no-egress for the agent, `egress` for the sidecar↔Stripe),
`sidecar.py` (holds the key + cap gate), `agent.py` (runaway + breach canary), `stripe_mock.py` (charges only
with the correct key).
