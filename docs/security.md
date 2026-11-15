# Security and threat model

## Scope

The reference kernel is an offline library over caller-supplied finite,
deterministic hypotheses and observations. It is not a vulnerability scanner,
exploit framework, wallet, or remote execution service. No test in this
repository targets a real system.

## Assets and guarantees

The primary asset is the integrity of a decision certificate and its declared
scope. `FiniteProblem.verify` recomputes compatibility and decision invariance;
it does not trust the controller's claimed compatible set or decision. The
verifier rejects malformed structures, unknown observations, duplicate keys,
empty hypothesis sets, and unsupported external-world scopes.

A `declared_hypothesis_class` certificate guarantees only that the decision is
invariant over the hypotheses supplied to the verifier. It does not establish
that the supplied class contains the real world. The benchmark deliberately
keeps an omitted-world expected failure visible.

## Threats considered

- forged or malformed certificates;
- duplicate or unknown evidence identifiers;
- contradictory observations that eliminate every declared hypothesis;
- hidden-world/oracle leakage into policy selection;
- negative or unmeasured costs being treated as free;
- nondeterministic ordering changing a result silently;
- stale scientific claims copied from synthetic experiments to real targets.

The tests cover these risks within the finite reference scope. Inputs are
validated by constructors and the CLI returns `ERROR` rather than silently
coercing malformed certificates into evidence.

## Threats not covered

The project does not provide sandboxing for arbitrary adapter code, cryptographic
attestation, protection against a malicious Python runtime, completeness of a
hypothesis class, probabilistic calibration, or security of external storage
and transport. Callers running adapters must isolate them and must supply an
independent validator for any claim beyond the declared class.

Cyber and DeFi experiments must remain local, authorized, and non-destructive.
No external target is part of the acceptance suite. Reproduction of a known
vulnerability is not a new-discovery claim.
