# CLI and JSON interface

The CLI is intentionally offline and deterministic. It is a thin interface over
the finite reference kernel, not a general domain API.

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps .
```

## Problem format

```json
{
  "hypotheses": [
    {"id": "h0", "observations": {"a": "0"}, "decision": "safe"},
    {"id": "h1", "observations": {"a": "1"}, "decision": "unsafe"}
  ],
  "observations": [{"id": "a", "cost": 1.0}]
}
```

Every hypothesis must provide a value for every declared observation. IDs must
be non-empty unique strings. Costs are finite non-negative real numbers in the
current reference model; strings, booleans, arrays, objects, NaN, and infinite
values are rejected by the kernel as well as by the CLI.

## Run and statuses

```bash
prism run problem.json --evidence '{"a":"0"}'
```

The command emits JSON with `status`, `decision`, `state`, and, when certified,
a certificate. Exit status is zero only for `CERTIFIED_DECISION`; an abstention
or user/data error returns 2. The current statuses are
`CERTIFIED_DECISION`, `ABSTAIN`, and `ERROR` for the run path. Missing,
unreadable, invalid-JSON, malformed, and non-object evidence inputs are
reported as controlled JSON errors without an internal traceback.

## Independent verification

```bash
prism verify-certificate problem.json certificate.json
```

This emits `{"status":"VERIFIED","valid":true}` only when the independent
finite verifier accepts the certificate. A structurally valid but false or
unsupported certificate returns `INVALID` and exits 2. A missing, unreadable,
or malformed certificate file returns controlled `ERROR` JSON. Certificates
with `external_world` scope are rejected because the reference kernel has no
external validator.

## Reproducibility and limitations

The CLI does not access hidden labels, external services, LLMs, or network
resources. It does not implement persistence, checkpoint/resume, probabilistic
semantics, or a remote API. These are explicit future work rather than hidden
features.
