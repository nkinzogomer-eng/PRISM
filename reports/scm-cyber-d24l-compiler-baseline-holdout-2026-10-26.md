# PRISM D2.4L — Typed compiler graph, real EVM controls, baseline and unseen holdout

Date: 2026-10-26. Experimental branch:
`research/scm-cyber-d24i-independent-holdout`. No changes to `main`.

**Engineering gate: PASS. Matched baseline superiority: NOT SHOWN.
Prospective target-specific discovery gate: NOT PASSED. Newly verified
vulnerability classes and zero-days: ZERO.**

## Auditable independent executions

- [GitHub Actions 40320210470](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40320210470):
  first green compiler AST + three independent EVM scenario gates, following
  [40319996466](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40319996466)
  initial red result caused by `FunctionCallOptions` wrapping a payable call.
- [40320613657](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40320613657):
  same synthetic contract, pinned Slither 0.11.6 independent baseline. PASS.
- [40321176635](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40321176635):
  first prospective unseen-source result. PASS of *accounting* protocol,
  with a dependency-origin hypothesis initially reported as a closure-wide
  candidate. This was not a finding about the selected contract.
- [40321707982](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40321707982):
  corrected target-versus-dependency attribution and detailed negative reason.
  The hypothesis engine remained frozen, and the 2 targets were unchanged.

## What became technically real

`prism/d24l_typed_graph.py` consumes Solidity compiler AST and uses semantic
declaration IDs for functions, state variables, internal call edges,
inheritance and overloads. It generates **conditional, unverified**
external-call-before-storage-write hypotheses. It does not pretend that
lexical token matches or mere candidates prove exploitability.

The reproducible native trial included untouched Solmate ERC4626 and its
dependencies alongside deliberately flawed and corrected **local-only**
reentrancy bank test contracts, compiled on Foundry 1.3.6 / Solidity 0.8.24:

| Gate | Observed result |
| --- | --- |
| Contracts in actual compiler build | 14 |
| Compiler-typed functions | 72 |
| Functions with unsupported/control-flow semantics | **27** |
| PRISM candidate on intentionally vulnerable bank `withdraw` | **1** |
| PRISM candidate on safe update-before-call `withdraw` | **0** |
| Native Foundry EVM scenarios | **3/3 passed** |
| Independent transfer observation | Attacker captures an extra 1 **local test ETH** from honest depositor in vulnerable bank |
| Independent corrected control | 0 extra local test ETH captured |
| New public-source vulnerabilities confirmed | **0** |

**No deployed chain, RPC, wallet, external funds or live attack.**

The earliest real build was RED because Solidity wraps
`msg.sender.call{value: amount}(... )` in `FunctionCallOptions`; mock AST
tests had omitted this real syntax shape. A new regression test and a
compiler-verified correction made it GREEN. This is verified error-driven
hardening, not proof of novel vulnerability discovery.

## Matched conventional detector — Slither

Pinned `slither-analyzer==0.11.6`, `reentrancy-eth`, original same synthetic
Solidity source, Solidity 0.8.24, same GitHub runner:

| Known lab label | PRISM structural proposer | Slither `reentrancy-eth` |
| --- | ---: | ---: |
| Deliberately reentrant `D24LUnsafeBank.withdraw` | 1 | 1 |
| Corrected `D24LGuardedBank.withdraw` | 0 | 0 |

The *independently authored EVM oracle*, not either analyzer, establishes
the value consequences. Equal detection here does **not** show superior
recall, specificity, runtime, cost, or ability to detect zero-days. Slither
performs its own compilation, whereas PRISM consumed previously emitted
compiler build-info: end-to-end wall clocks are not directly comparable.

## Actual prospective test with frozen input and engine

The unmodified engine blob `40565cc336d85971b129f042b7fb1073470d6d73`
was **published before selecting/inspecting targets**. The exact immutable
target manifest was separately published at GitHub commit
`52fecc553e5f6affb8f4bc0780d2f5606612bbfc`.
The engine was **not modified** in response to results.

| Previously unused specific target | Compilation | Hypotheses on chosen target | Exact evidence and unknowns |
| --- | --- | ---: | --- |
| OpenZeppelin `AccessManager.sol` (`11565e5…`) | **FAILED** | **0 / UNKNOWN** | Original source and dependencies require `^0.8.31`, preregistered solc was `0.8.24`; no typed analysis possible under frozen protocol. |
| Aave V3 `Pool.sol` (`782f519…`) | **PASS** | **0 / UNKNOWN** | Compiler accepted source closure: 46 contracts, 379 functions, **228 with unsupported/control-flow shapes**. One hypothesis in `IncentivizedERC20` **dependency constructor**, not in selected `Pool.sol`. |

This is deliberately scored as **zero target-specific candidates**;
the **one dependency-only candidate is unverified** and is not a Pool finding.
The first report included a closure-wide count of one. The corrected report
separates the origin without changing PRISM's frozen rules or swapping the
targets. Neither result is evidence that either production contract is safe.

The holds measured **compiler/AST graph coverage and source-generated
hypotheses only**, not ground-truth vulnerability recall. No isolated native
economic/stateful verifier was executed against these new target contracts.

## Cost and reproducibility limits

- No model calls or GPU required. CPU-only on an ordinary hosted runner.
- One green compiler/native run logged about 0.618 seconds for the local
  compilation/EVM experiment **after source download**; another run logged
  about 0.731 seconds. These are not cross-tool or consumer-hardware speeds.
- **378 full-project Python tests**: all normal tests pass with one previously
  documented expected failure (377 regular passes, one expected failure).
- Persistent CI artifacts include AST evidence, native traces, frozen
  target output, baseline JSON and logs, subject to GitHub artifact retention.

## Specific failure causes, next falsifiable iteration

1. **Frozen compiler version mismatch:** add safe pragma-aware version
   selection and pinned compiler matrix before selecting another blind
   cohort. Do not retroactively score the same OpenZeppelin source as blind.
2. **Lossy control-flow/modifiers:** current bounded AST extractor abstains
   on 228/379 functions in the Aave source closure. Build typed CFG,
   modifier expansion, interprocedural effects and storage aliases; validate
   each through metamorphic positive and negative EVM controls.
3. **Dependency attribution:** always preserve both whole-closure and
   exact-target candidate counts, and require verified source location.
4. **Weak family coverage:** mere call-before-write is a known heuristic;
   discover obligations from assets, authorization, debt/liquidation,
   state-machine transitions and external economic assumptions; require an
   independent witness before calling anything a violation.
5. **Scientific comparison:** establish a larger, independently labeled and
   blinded corpus with the same CPU/time/memory budgets for PRISM and
   Slither/Echidna or Medusa. Compare recall, precision, abstention,
   execution cost, external verification and unique verified discoveries.
6. **Ciel** remains separate: it may propose hypotheses through a strict
   JSON contract, while PRISM must verify or return UNKNOWN, never silently
   turn a suggested hypothesis into a finding.

**Evidence-bounded conclusion:** D2.4L improves compiler realism and
verification discipline; it has **not** yet demonstrated new classes,
zero-days or superiority to a conventional analyzer. Those goals remain
testable research hypotheses, not promises of inevitable success.
