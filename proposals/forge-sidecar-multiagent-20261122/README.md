# forge sidecar, multi-agent budgets (Docker, container-tier), 2026-11-22

Extends the #93 sidecar (`proposals/forge-sidecar-demo-20261121`, unchanged) from one agent to several.
Each agent gets **its own budget**, and the whole swarm shares **one total budget**. No agent holds an API
key. One sidecar holds the only key and decides every spend.

```sh
./validate.sh      # clean run, audit, sidecar restart, audit again; exit 0 only if every audit passes
```

## What it does

- **One log per agent, one log for the swarm.** Each spend becomes a tentative 128-byte record in two
  escrow logs: the agent's own (its cap, its expiry) and the swarm's (the total cap). The compiled, proved
  Leg-1 Dafny verifier from #91 checks each log in full. The key is used only if **both** verdicts are
  `ACCEPT`.
- **One writer.** A lock serializes every spend, so parallel requests cannot both see the same balance.
- **Per-agent policy** (`policy.json`): cap, expiry, allowed tools, call limit, bearer token.
- **Isolation.** Each agent is on its own `internal: true` network: it reaches only the sidecar, not the
  paid API, not the internet, not the other agents.
- **Restarts.** Logs are written to a volume with `fsync` before the key is used. On start the sidecar
  reloads each log and re-verifies it with the proved verifier; a log that does not verify stops the
  sidecar (fail closed).

## Actual result (Docker 28.5.1, macOS; three runs of `validate.sh`, all exit 0)

```
[support]  15 parallel x $3.00 stripe.refund: 6 ACCEPT, 9 refused ['REJECT_OVER_CAP']        cap $20.00
[research] 30 parallel x $0.10 x402.fetch:   20 ACCEPT, 10 refused ['REJECT_OVER_CAP']        cap  $2.00
[coder]    (prompt-injected) try $5,000: REJECT_OVER_CAP
[coder]    (prompt-injected) try a tool it was not given: TOOL_NOT_ALLOWED
[coder]    (prompt-injected) try a negative amount: BAD_AMOUNT
[coder]    (prompt-injected) try a guessed token: UNKNOWN_AGENT
[coder]    40 parallel x $0.10 x402.fetch: 0 ACCEPT, 40 refused ['swarm:REJECT_OVER_CAP']     cap  $1.00
           swarm gross $20.00 / cap $20.00 (the agents' caps add up to $23.00: the swarm cap binds)
after a sidecar restart: logs reloaded and re-verified ACCEPT; one more spend refused
AUDIT PASSED (twice per run): 20 checks each
```

Every agent also reports: API key in its environment `False`; paid API, internet and other agents
`BLOCKED`. Which agent uses the shared budget first changes from run to run; the audit checks invariants,
not one order.

The audit (`auditor.py`, a trusted test harness) checks, per agent and for the swarm: gross ≤ cap; calls ≤
limit; the log re-verifies `ACCEPT` with the proved verifier; what the mock paid API really charged equals
the log's gross; only allowed tools reached it; swarm gross equals the sum of the agents' gross; one
upstream charge per swarm step.

## Honest labels

| Part | Label |
| --- | --- |
| Verdict on one log: gross ≤ cap, conservation, no duplicate step, dense sequence, expiry | PROVED (Dafny model, #91) |
| Compiled verifier that the sidecar runs | NATIVE CHECK (unverified compiler) |
| Record encoder; "accepted only if both logs accept" and "both logs get the same spend"; tokens; tool allow-list; call limit; reload; forwarding | NATIVE CHECK (this code, not proved) |
| Isolation | container-tier: shared kernel; a kernel escape needs a microVM |
| The runs above | FINITE TEST on one machine; mock paid API; no real money |

`end_to_end=false`. The bound "an agent can lose at most its cap" holds only for spends routed through the
sidecar; anything the agent can do without the key is out of scope.

## Known issues

- Under a burst of 40 parallel connections, one connection was reset in 1 of 3 runs (the sidecar's listen
  queue was raised to 256; the cause is not found). The request is reported as `CONNECTION_ERROR`; it was
  not charged, and the audit still passed.
- The upstream call is not idempotent: a crash between recording a spend and forwarding it leaves a recorded
  spend that was never charged (under-pay, never over-cap). A real API needs an idempotency key and a
  reconcile step.
- Each spend re-verifies both logs in full (as in #93): cost grows with log length.
- The admin token and the demo key are fixed strings in this demo, not secrets.

## Files

`sidecar/sidecar_multi.py` (the multi-log gate) with the compiled verifier and keys copied from #93;
`policy.json`; `agents/agent.py` (one script, three roles); `upstream_mock.py` (charges only with the key,
keeps a ledger); `auditor.py`; `docker-compose.yml`; `validate.sh`.
