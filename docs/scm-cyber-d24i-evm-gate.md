# D2.4I-EVM — bounded real EVM mutation and evidence integrity gate

This is an **engineering hardening gate**, not a blind vulnerability hunt.
The Solidity implementation is the pre-existing, local D2.2 lab fixture
`benchmarks/defi/d22/src/MultiRisk.sol`, with four labelled variants:
three deliberate defects (oracle write, debt-unsafe withdrawal, unfunded
repayment) and one safe control. No external blockchain, account funds or
permissionless target interaction is involved.

Foundry v1.3.6 independently executes EVM bytecode and checks the prewritten
stateful invariants. It does not import the PRISM Python verifier or its
expected result. `scripts/d24i_evm_bridge.py` requires the exact independent
test inventory, failure-reason signatures, consistent process exit code,
token conservation and the negative safe control. A wrong failure, missing
test or malformed JSON aborts the claim, never counts as a discovery.

The *actual* Foundry status of each invariant becomes a read-only trace of
`property_holds` booleans. The new generic Ciel→PRISM contract checks the
same boolean safety obligation against four separately observed variants,
records source SHA-256 and replay hashes, and refuses to elevate the result
to `VERIFIED` or an unpublished vulnerability. This is a deliberate limited
bridge: unlike full balance/debt traces, boolean invariant results rely on
the independent Foundry assertion itself for semantics.

## Budget ladder and adversity

Start at 64 runs × 32 steps per stateful invariant, then escalate to 256 × 64
only if the known mutant is missed or a spurious property fails. Preserve all
misses and timings, and abort the engineering gate if the max budget still
fails. Each budget runs all four variants, with no silent filtering of errors.

After that first evidence gate, the **second, harder** gate repeats the
experiment over eight preregistered seeds (1–8), beginning with only 32 runs
× 16 steps, then 64 × 32 and finally 256 × 64 as required. The seed and
Foundry version are recorded with raw stdout for replay. All initial misses
are kept in the result even when a later budget catches them; per-seed cost
and coverage are recorded separately.
No human tuning of search seeds or oracle after reading results is allowed
without documenting the effect on the benchmark; this cohort is prelabelled
and is never counted as a blind holdout.

Locally, pure Python adversarial tests validate synthetic Foundry JSON
parsing: missing/extra tests, duplicate results, malformed JSON, unrelated
revert, token conservation, false process success, negative-control mutation,
known-mutant misses and false positives. CI runs the actual Foundry bytecode.

## Hard GO/NO-GO

- GO engineering only if all three known mutants are identified, all nine
  expected-negative cross-property controls remain negative, the safe control
  remains negative, evidence hashes are present and PRISM/Ciel status is
  UNVERIFIED pending independent attestation.
- NO-GO scientific until the program is not preselected by labelled defects,
  the hypothesis semantic correctness is externally established, full traces
  are replayed against a second independent EVM, and recall/precision/cost
  comparisons on real contracts use a true blind holdout.
