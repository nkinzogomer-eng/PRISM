"""D2.4I: portable Ciel -> PRISM hypothesis verification boundary.

Ciel (or any optional generator) supplies *only* a structured property, target
hash and resource budget. A trusted PRISM host must inject the observation
adapter; there is no supplied code, executable, oracle, expected answer or
observation in the request. The interpreter is deterministic and LLM-free.

A counterexample is relative to the injected observation trace, NOT proof of
a vulnerability, a zero-day, or whole-program unsafety. Ciel must perform its
own evidence integrity assessment before marking any task VERIFIED.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from time import perf_counter
from typing import Callable


SCHEMA = "scm.prism.hypothesis-request.v1"
RESULT_SCHEMA = "scm.prism.hypothesis-check.v1"
CIEL_OUTPUT_SCHEMA = "scm.prism.ciel-capability.v2"
CIEL_CAPABILITY_MANIFEST = {
    "name":"prism.cyber.verify_hypothesis",
    "version":"0.1.0",
    "description":"Bounded deterministic check of externally proposed finite-trace hypotheses",
    "idempotent":True,
    "reversible":True,
    "side_effects":[],
    "requires_runtime":"EXTERNAL",
    "permissions":["local_source_read"],
    "status":"REQUIRES_EXTERNAL_RUNTIME",
}
_IDENT = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,99}$")
_VAR = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_LIMIT = 10**30
_COMPARATORS = {"eq", "ne", "ge", "gt", "le", "lt"}
_ARITHMETIC = {"add", "sub", "mul"}


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode()


def _hash(obj: object) -> str:
    return sha256(_canonical(obj)).hexdigest()


def _reject(message: str):
    raise ValueError("invalid hypothesis contract: " + message)


def _keys(obj: object, required: set[str], optional: set[str] = frozenset()):
    if type(obj) is not dict or not required <= obj.keys() or not obj.keys() <= required | optional:
        _reject("missing or unexpected fields")


def _ident(value: object) -> bool:
    return type(value) is str and _IDENT.fullmatch(value) is not None


def _limit_int(value: object) -> bool:
    return type(value) is int and abs(value) <= _LIMIT


def _validate_expr(node: object, *, depth: int = 0) -> int:
    if depth > 8:
        _reject("predicate nesting too deep")
    if type(node) is not dict:
        _reject("predicate expression must be an object")
    if "const" in node:
        _keys(node, {"const"})
        if not (_limit_int(node["const"]) or type(node["const"]) is bool):
            _reject("constant must be a bounded integer or boolean")
        return 1
    if "var" in node:
        _keys(node, {"var"})
        if type(node["var"]) is not str or _VAR.fullmatch(node["var"]) is None:
            _reject("invalid observed variable name")
        return 1
    _keys(node, {"op", "left", "right"})
    if type(node["op"]) is not str or node["op"] not in _COMPARATORS | _ARITHMETIC:
        _reject("unrecognized predicate operator")
    size = 1 + _validate_expr(node["left"],depth=depth+1) + _validate_expr(node["right"],depth=depth+1)
    if size > 63:
        _reject("predicate node budget exceeded")
    return size


def _has_observed_variable(node: dict) -> bool:
    if "var" in node:
        return True
    if "op" in node:
        return _has_observed_variable(node["left"]) or _has_observed_variable(node["right"])
    return False


def _eval_expr(node: dict, values: dict) -> int | bool:
    if "const" in node:
        return node["const"]
    if "var" in node:
        if node["var"] not in values:
            raise KeyError("missing observed variable")
        return values[node["var"]]
    a = _eval_expr(node["left"],values)
    b = _eval_expr(node["right"],values)
    op = node["op"]
    if op == "eq":
        return type(a) is type(b) and a == b
    if op == "ne":
        return type(a) is not type(b) or a != b
    if type(a) is not int or type(b) is not int:
        raise TypeError("ordered/arithmetic predicate requires integers")
    if op == "ge": return a >= b
    if op == "gt": return a > b
    if op == "le": return a <= b
    if op == "lt": return a < b
    if op == "add": result = a + b
    elif op == "sub": result = a - b
    elif op == "mul": result = a * b
    else: raise AssertionError("operator not validated")
    if not _limit_int(result):
        raise OverflowError("arithmetic bound exceeded")
    return result


def _read_pinned_source(root: Path, source: dict) -> str:
    _keys(source,{"path","sha256","language"})
    if source["language"] not in ("python", "solidity"):
        _reject("unsupported source language")
    if type(source["path"]) is not str or not source["path"] or len(source["path"]) > 240:
        _reject("invalid source path")
    relative = Path(source["path"])
    suffix = ".py" if source["language"] == "python" else ".sol"
    if relative.is_absolute() or ".." in relative.parts or relative.suffix != suffix:
        _reject("path escapes approved target or wrong extension")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        _reject("invalid source digest")
    boundary = root.resolve(strict=True)
    target = boundary / relative
    # Deny even in-root symlinks to keep provenance immutable under aliases.
    cursor = boundary
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            _reject("symlinks not allowed")
    if not target.resolve(strict=True).is_relative_to(boundary) or not target.is_file():
        _reject("source outside approved root")
    if target.stat().st_size > 1_000_000:
        _reject("source byte budget exceeded")
    current = sha256(target.read_bytes()).hexdigest()
    if current != source["sha256"]:
        _reject("source precondition fingerprint changed")
    return current


def verify_hypothesis(request: dict, *, authorized_root: Path,
                      authorized_local: bool = False,
                      independent_observer: Callable[[dict], dict] | None = None) -> dict:
    """Check a generic finite-trace invariant without depending on Ciel.

    An adapter must be provided out-of-band by the trusted PRISM runtime,
    never from the model's serialized request. The observer is assumed
    policy-scoped by the host, not cryptographically attested by this method.
    """
    if authorized_local is not True:
        raise PermissionError("explicit authorization to inspect local source required")
    _keys(request,{"schema","mission_id","task_id","hypothesis_id","proposer",
                   "source","property","budget","execution_policy"})
    if request["schema"] != SCHEMA or request["execution_policy"] != "LOCAL_READ_ONLY":
        _reject("schema or execution policy")
    if not all(_ident(request[x]) for x in ("mission_id","task_id","hypothesis_id")):
        _reject("invalid correlation identifier")
    proposer = request["proposer"]
    _keys(proposer,{"kind","id"})
    if proposer["kind"] not in ("CIEL","HUMAN","DETERMINISTIC") or not _ident(proposer["id"]):
        _reject("invalid proposer")
    prop = request["property"]
    _keys(prop,{"kind","family","predicate"})
    if prop["kind"] != "FINITE_TRACE_INVARIANT" or not _ident(prop["family"]):
        _reject("unsupported property representation")
    if (type(prop["predicate"]) is not dict
            or type(prop["predicate"].get("op")) is not str
            or prop["predicate"].get("op") not in _COMPARATORS):
        _reject("predicate root must compare two expressions")
    _validate_expr(prop["predicate"])
    if not _has_observed_variable(prop["predicate"]):
        _reject("an observation-dependent predicate is required")
    budget = request["budget"]
    _keys(budget,{"max_observations"})
    if type(budget["max_observations"]) is not int or not 1 <= budget["max_observations"] <= 128:
        _reject("bounded observation count required")
    started = perf_counter()
    digest = _read_pinned_source(authorized_root,request["source"])
    report = {
        "schema":RESULT_SCHEMA,
        "mission_id":request["mission_id"],"task_id":request["task_id"],
        "hypothesis_id":request["hypothesis_id"],
        "request_sha256":_hash(request),"source_sha256":digest,
        "predicate_sha256":_hash(prop["predicate"]),
        "status":"INCOMPLETE_UNKNOWN","witness":None,
        "observations_checked":0,"replay_sha256":None,
        "independent_observer_id":None,
        "program_code_executed_by_prism":False,
        "verifier":"PRISM_DETERMINISTIC_FINITE_TRACE_PREDICATE_V1",
        "verification_scope":"OBSERVATIONS_ONLY_NOT_PROGRAM_SAFETY",
        "property_semantic_validity":"UNATTESTED_EXTERNAL_PROPOSAL",
        "observer_independence_cryptographically_proven":False,
        "ciel_verification_state":"UNVERIFIED",
        "claim_of_new_vulnerability":False,
        "needs_independent_attestation":True,
    }
    if independent_observer is None:
        report["reason"]="NO_INDEPENDENT_OBSERVATION_ADAPTER"
        return report
    raw = independent_observer({
        "mission_id":request["mission_id"],"task_id":request["task_id"],
        "hypothesis_id":request["hypothesis_id"],
        "source_sha256":digest,
        "max_observations":budget["max_observations"],
    })
    _keys(raw,{"observer_id","source_sha256","observations"})
    if (not _ident(raw["observer_id"]) or raw["observer_id"] == proposer["id"]
            or raw["source_sha256"] != digest):
        _reject("observer not distinct or source fingerprint changed")
    rows = raw["observations"]
    if (type(rows) is not list or not 1 <= len(rows) <= budget["max_observations"]):
        _reject("missing or over-budget independent observations")
    ids = set()
    for row in rows:
        _keys(row,{"event_id","values"})
        if not _ident(row["event_id"]) or row["event_id"] in ids:
            _reject("duplicate or invalid event identifier")
        ids.add(row["event_id"])
        values = row["values"]
        if type(values) is not dict or len(values) > 64 or any(
            type(k) is not str or _VAR.fullmatch(k) is None
            or not (_limit_int(v) or type(v) is bool)
            for k,v in values.items()
        ):
            _reject("unsupported observation values")
    report["independent_observer_id"] = raw["observer_id"]
    report["replay_sha256"] = _hash(raw)
    unknown = False
    for row in rows:
        report["observations_checked"] += 1
        try:
            holds = _eval_expr(prop["predicate"],row["values"])
        except (KeyError, TypeError, OverflowError):
            unknown = True
            continue
        if holds is False and report["witness"] is None:
            # Evidence metadata only. Never echo private raw observation values.
            report["witness"] = {"event_id":row["event_id"],
                                 "values_sha256":_hash(row["values"]),
                                 "claim_scope":"LOCAL_OBSERVED_COUNTEREXAMPLE_ONLY"}
    if report["witness"] is not None:
        report["status"]="LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY"
    elif unknown:
        report["status"]="INCOMPLETE_UNKNOWN"
        report["reason"]="MISSING_OR_UNMODELED_OBSERVATION_VALUE"
    else:
        report["status"]="NO_COUNTEREXAMPLE_OBSERVED_NOT_SAFE"
    # Replay must not silently survive mutation of the checked source.
    if _read_pinned_source(authorized_root,request["source"]) != digest:
        _reject("source changed during observation")
    report["elapsed_seconds"]=perf_counter()-started
    return report


def ciel_hypothesis_capability_result(result: dict) -> dict:
    """Return the Ciel-compatible observation envelope, never VERIFICATION.

    The host calls this only on the direct return of verify_hypothesis, not
    on arbitrary model-provided serialized data. Ciel still assesses integrity.
    """
    if (type(result) is not dict or result.get("schema") != RESULT_SCHEMA
            or result.get("status") not in {
                "INCOMPLETE_UNKNOWN", "LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY",
                "NO_COUNTEREXAMPLE_OBSERVED_NOT_SAFE"}
            or result.get("claim_of_new_vulnerability") is not False
            or result.get("needs_independent_attestation") is not True
            or result.get("ciel_verification_state") != "UNVERIFIED"):
        raise ValueError("invalid or inflated hypothesis verification result")
    for identifier in ("mission_id","task_id","hypothesis_id"):
        if not _ident(result.get(identifier)):
            raise ValueError("missing Ciel evidence correlation identifier")
    if (result["status"] == "LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY"
            and (result.get("witness") is None or
                 not isinstance(result.get("replay_sha256"),str))):
        raise ValueError("witness lacks trace provenance")
    return {
        "schema":CIEL_OUTPUT_SCHEMA,
        "capability":CIEL_CAPABILITY_MANIFEST["name"],
        "mission_id":result["mission_id"],"task_id":result["task_id"],
        "execution_policy":"LOCAL_READ_ONLY",
        "requires_external_runtime":True,
        "observation":result,
        "ciel_verification_state":"UNVERIFIED",
        "needs_independent_attestation":True,
        "claim_of_new_vulnerability":False,
    }
