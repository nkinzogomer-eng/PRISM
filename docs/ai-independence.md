# PRISM and AI Independence

PRISM's core must operate correctly without an AI model, network access, embeddings, or learned parameters.

## Required boundary

The certified path is deterministic:

```text
problem contract -> evidence state -> compatible hypotheses
-> decision partition -> operation selection -> verifier
```

An AI may optionally propose candidates, summaries, priorities, or interpretations, but it is never authoritative.

## AI may assist with

- proposing candidate operations;
- ranking already-valid operations;
- suggesting representations;
- summarizing traces for a human;
- translating a domain into an adapter draft.

These proposals are untrusted hints. They must pass the same contract, budget, provenance, and verifier checks as any other proposal.

## AI may not control

- the definition of a certified decision;
- the compatible-hypothesis set without an explicit adapter operation;
- the truth of an observation;
- certificate acceptance;
- hidden labels or test outcomes;
- silent changes to assumptions;
- deletion of contradictory evidence;
- final claims beyond the declared hypothesis class.

## Fallback requirement

Every AI-assisted run must have a non-AI fallback policy. If the AI is unavailable, inconsistent, too expensive, or outside its declared budget, PRISM continues with deterministic selection or abstains.

The benchmark must compare deterministic PRISM, PRISM with optional AI suggestions, and a deterministic baseline with the same operation budget. Any gain must survive removal of the AI component if the claim concerns the PRISM core.

## Audit requirement

AI outputs are recorded as untrusted proposals with model/version metadata, request identifier where available, cost, and acceptance/rejection status. The verifier never consumes an AI claim as proof.
