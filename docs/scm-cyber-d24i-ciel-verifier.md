# D2.4I — PRISM as a deterministic checker for Ciel-proposed hypotheses

This extends the D2.4G `scm.prism.ciel-capability.v1` *output* envelope with a
separate, strict **input** contract: `scm.prism.hypothesis-request.v1`. It does
not change the Ciel repository. PRISM is provider-independent and runs with
`AI_ENABLED=false`; generated hypotheses may come from Ciel, a person or a
deterministic generator.

## Responsibility and trust boundaries

1. **Ciel proposes** a goal-conditioned property, target file digest and
   resource budget. It cannot submit program code, a verifier implementation,
   observations, a forged oracle, an expected verdict or a claimed proof.
2. **PRISM validates** the JSON shape, authorized root path, source SHA-256,
   no-symlink rule, language, policy, correlation ids and bounded predicate
   language. It never executes the target source in this checker.
3. **PRISM host (not Ciel)** injects a preapproved observation provider outside
   the serialized request. The provided observer is merely required to have
   an ID different from the proposer, to return the pinned source SHA-256 and
   a bounded unique trace. This does **not cryptographically prove** physical
   independence, honesty, or that real target code ran. Host must audit
   adapter identity and enforce execution isolation/time limits separately.
4. **A deterministic checker** evaluates only finite trace predicates over
   bounded integers/booleans with operations eq/ne/le/lt/ge/gt/add/sub/mul.
   The *same* interpreter handles arbitrary named property families, e.g.
   collateralization, asset conservation or authorization state invariants;
   no family-specific external model or scanner is needed for checking a
   populated trace. It cannot automatically infer a correct economic model.
5. **The output is untrusted until reviewed**. A mismatching trace creates
   `LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY`; agreement yields
   `NO_COUNTEREXAMPLE_OBSERVED_NOT_SAFE`; missing independent observations or
   data yields `INCOMPLETE_UNKNOWN`. Ciel's own verification engine still has
   to assess integrity and seek independent attestation. PRISM sets
   `ciel_verification_state=UNVERIFIED` unconditionally.

## Example input (source hash is an illustration, not a real target)

```json
{
  "schema": "scm.prism.hypothesis-request.v1",
  "mission_id": "mission:1",
  "task_id": "task:1",
  "hypothesis_id": "hypothesis:collateral",
  "proposer": {"kind": "CIEL", "id": "ciel.planner"},
  "source": {
    "path": "contract.sol",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "language": "solidity"
  },
  "property": {
    "kind": "FINITE_TRACE_INVARIANT",
    "family": "collateralization",
    "predicate": {
      "op": "ge", "left": {"var": "assets"}, "right": {"var": "liabilities"}
    }
  },
  "budget": {"max_observations": 3},
  "execution_policy": "LOCAL_READ_ONLY"
}
```

Python interface:

```python
from prism.hypothesis_contract import verify_hypothesis
result = verify_hypothesis(
    request,
    authorized_root=approved_project_root,
    authorized_local=True,
    independent_observer=preapproved_local_observer,
)
```

`ciel_hypothesis_capability_result(result)` wraps the return into
`scm.prism.ciel-capability.v2` with capability name
`prism.cyber.verify_hypothesis`. The manifest declares `EXTERNAL`,
`local_source_read`, idempotent and reversible, with no side effects. This
matches the field names expected by Ciel's capability manifest contract but
does not mean the capability is installed or registered in the Ciel runtime.

Only a host-owned adapter may provide observations, never JSON from Ciel.
Data is content-hashed for replay and source is checked again after the call.
The digest is an integrity control, not a cryptographic attestation.

## Measured test gate and remaining unknowns

Adversarial tests cover fabricated evidence injection, scope traversal,
symlinks, stale hashes, same-proposer observer, mismatched provenance,
duplicate/over-budget traces, missing values, arbitrary operators, simple
integer invariants, meaningful counterexample and no-safety abstention.
All observations in these tests are *synthetic fixtures*. This does not
validate an ERC-20 or DeFi deployment, discover a zero-day, or establish a
semantic invariant that should hold in the first place.

Next prerequisites for real Ciel integration:

- A signed/attested, independent EVM/Python trace collector with execution
  sandbox, permissions, reproducibility and resource quotas.
- A semantic obligation catalog backed by public specifications or human
  approved economic assumptions, so arbitrary proposals cannot manufacture
  logically false but irrelevant invariants.
- Multi-contract state/alias semantics, stateful counterexample minimization,
  independent replay in a second engine and source/chain/version pinning.
- A Ciel EXTERNAL capability adapter with observation integrity assessment,
  ledger evidence IDs, checkpoints, retry policy and no implicit verification.
- Blind labeled benchmarks and cost/performance comparison on ordinary CPUs.

Until these exist, the contract is an honest proof boundary prototype, **not
the full autonomous zero-day verification engine**.
