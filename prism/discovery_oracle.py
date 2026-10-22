"""D1.0 in-memory property oracle for a PINNED, GENERATED local corpus.

This checks concrete unauthorized-disclosure witnesses, not universal program
safety. Generated code is trusted benchmark input only; never run untrusted
source code or remote targets through this in-process oracle.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from time import perf_counter

from benchmarks.d10_dev.specification import VERSION

ID_RE = re.compile(r"(?:q|a)[0-9]{2}[ab]\Z")
PROPERTY_CLASSES = {
    "SQLI_UNEXPECTED_OWNER": "SQLI",
    "BAC_CROSS_TENANT_READ": "BAC",
}


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf8"))
    if not isinstance(value, dict):
        raise ValueError("manifest must be an object")
    return value


class Corpus:
    """Immutable verified snapshot. The oracle must never act on stale files."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve(strict=True)
        self.public = _read_json(self.root / "public.json")
        self.oracle = _read_json(self.root / "oracle.json")
        if self.public.get("schema") != VERSION or self.oracle.get("schema") != VERSION:
            raise ValueError("unsupported or mismatched manifest version")
        rows = self.public["cases"]
        truth = self.oracle["oracle"]
        if not isinstance(rows, list) or not isinstance(truth, list):
            raise ValueError("invalid manifest rows")
        if len(rows) != 24 or len(truth) != 24:
            raise ValueError("incomplete frozen D1.0 development corpus")
        self.rows = {}
        self.truth = {}
        expected_paths = set()
        for public_case in rows:
            case_id = public_case["case_id"]
            if not isinstance(case_id, str) or not ID_RE.fullmatch(case_id):
                raise ValueError("invalid case identifier")
            if case_id in self.rows:
                raise ValueError("duplicate public case")
            if public_case.get("property_id") not in PROPERTY_CLASSES:
                raise ValueError("unrecognized property")
            relative = "cases/" + case_id + ".py"
            if public_case.get("path") != relative:
                raise ValueError("unexpected or unsafe path")
            if public_case.get("entrypoint") != "run":
                raise ValueError("unexpected entrypoint")
            filename = self.root / relative
            if not filename.is_file() or filename.is_symlink():
                raise ValueError("missing or symlinked corpus source")
            actual = hashlib.sha256(filename.read_bytes()).hexdigest()
            if actual != public_case["source_sha256"]:
                raise ValueError("corpus source integrity failure for " + case_id)
            expected_paths.add(filename.name)
            self.rows[case_id] = public_case
        actual_paths = {path.name for path in (self.root / "cases").iterdir()}
        if actual_paths != expected_paths:
            raise ValueError("unexpected/missing corpus files")
        for oracle_case in truth:
            case_id = oracle_case["case_id"]
            if case_id in self.truth or case_id not in self.rows:
                raise ValueError("missing or duplicate oracle mapping")
            if oracle_case.get("property_id") != self.rows[case_id]["property_id"]:
                raise ValueError("oracle property mismatch")
            if oracle_case.get("ground_truth") not in {"vulnerable", "patched"}:
                raise ValueError("invalid oracle truth label")
            if oracle_case.get("severity") != "unrated":
                raise ValueError("D1.0 has no justified severity ratings")
            self.truth[case_id] = oracle_case
        if set(self.rows) != set(self.truth):
            raise ValueError("missing truth entries")
        public_rows_hash = hashlib.sha256(
            (json.dumps(rows, sort_keys=True, indent=2, ensure_ascii=True) + "\n")
            .encode("utf8")
        ).hexdigest()
        if (public_rows_hash != self.public["public_manifest_sha256"] or
                public_rows_hash != self.oracle["public_manifest_sha256"]):
            raise ValueError("public/oracle provenance mismatch")
        spec_path = (Path(__file__).resolve().parents[1] /
                     "benchmarks/d10_dev/specification.py")
        if hashlib.sha256(spec_path.read_bytes()).hexdigest() != self.public[
                "source_specification_sha256"]:
            raise ValueError("fixture generator provenance mismatch")
        pairs = {}
        for row in rows:
            pairs.setdefault(row["pair_id"], []).append(row["case_id"])
        if len(pairs) != 12 or any(len(ids) != 2 for ids in pairs.values()):
            raise ValueError("invalid paired-case inventory")
        if any(Counter(self.truth[i]["ground_truth"] for i in ids) !=
               Counter({"vulnerable": 1, "patched": 1}) for ids in pairs.values()):
            raise ValueError("a pair lacks exactly one positive and one negative")
        properties = Counter(row["property_id"] for row in rows)
        if properties != Counter({"SQLI_UNEXPECTED_OWNER": 12,
                                 "BAC_CROSS_TENANT_READ": 12}):
            raise ValueError("wrong property-family balance")

    def _load_function(self, case_id: str):
        if case_id not in self.rows:
            raise ValueError("unknown case")
        row = self.rows[case_id]
        path = self.root / row["path"]
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["source_sha256"]:
            raise ValueError("source modified since initial manifest verification")
        ns = {"__builtins__": __builtins__}
        exec(compile(raw, str(path), "exec"), ns, ns)
        function = ns.get("run")
        if not callable(function):
            raise ValueError("missing run function")
        return function

    def _check_sqli(self, run, witness: dict) -> dict:
        supplied = witness.get("supplied")
        if not isinstance(supplied, str) or len(supplied) > 120:
            raise ValueError("witness must have a short supplied string")
        if "\x00" in supplied:
            raise ValueError("NUL is not supported")
        def execute(value: str):
            with sqlite3.connect(":memory:") as db:
                db.execute("CREATE TABLE records (owner TEXT NOT NULL)")
                db.executemany("INSERT INTO records(owner) VALUES (?)",
                               [("alice",), ("bob",)])
                result = run(db, value)
                if not isinstance(result, list) or any(
                        item not in {"alice", "bob"} for item in result):
                    raise ValueError("invalid fixture output")
                return result
        own = execute("alice")
        expected_ok = own == ["alice"] and execute("bob") == ["bob"]
        try:
            observed = execute(supplied)
            error = None
        except sqlite3.Error as exc:
            observed = []
            error = type(exc).__name__
        return {
            "property": "SQLI_UNEXPECTED_OWNER",
            "benign_control_pass": expected_ok,
            "unauthorized_disclosure": "bob" in observed and supplied != "bob",
            "observed_owners": sorted(observed),
            "error": error,
        }

    def _check_bac(self, run, witness: dict) -> dict:
        principal = witness.get("principal")
        record_key = witness.get("record_key")
        if principal not in {"alice", "bob"} or record_key not in {
                "a-doc", "b-doc"}:
            raise ValueError("unsupported BAC witness")
        records = {
            "a-doc": {"owner": "alice", "value": "ALICE_SECRET"},
            "b-doc": {"owner": "bob", "value": "BOB_SECRET"},
        }
        expected_ok = (run(records, "alice", "a-doc") == "ALICE_SECRET" and
                       run(records, "bob", "b-doc") == "BOB_SECRET")
        value = run(records, principal, record_key)
        return {
            "property": "BAC_CROSS_TENANT_READ",
            "benign_control_pass": expected_ok,
            "unauthorized_disclosure": (
                principal == "alice" and record_key == "b-doc"
                and value == "BOB_SECRET"
            ),
            "observed_value": value,
        }

    def observe(self, case_id: str, witness: dict) -> dict:
        if case_id not in self.rows:
            raise ValueError("case out of scope")
        if not isinstance(witness, dict):
            raise ValueError("witness must be an object")
        started = perf_counter()
        run = self._load_function(case_id)
        property_id = self.rows[case_id]["property_id"]
        if property_id == "SQLI_UNEXPECTED_OWNER":
            outcome = self._check_sqli(run, witness)
        else:
            outcome = self._check_bac(run, witness)
        outcome["case_id"] = case_id
        outcome["oracle_wall_seconds"] = perf_counter() - started
        return outcome

    def validate_all(self) -> dict:
        """Abort on missing proofs, mislabeled patch, or poisoned benchmark."""
        records = []
        count_by_class = Counter()
        for case_id in sorted(self.rows):
            truth = self.truth[case_id]
            outcomes = [self.observe(case_id, w) for w in truth["witnesses"]]
            if not outcomes or not all(x["benign_control_pass"] for x in outcomes):
                raise ValueError("broken benign functionality for " + case_id)
            violated = any(x["unauthorized_disclosure"] for x in outcomes)
            expected = truth["ground_truth"] == "vulnerable"
            if violated != expected:
                raise ValueError("witness/label contradiction for " + case_id)
            count_by_class[(self.rows[case_id]["property_id"], expected)] += 1
            records.append({
                "case_id": case_id,
                "property_id": self.rows[case_id]["property_id"],
                "ground_truth": truth["ground_truth"],
                "canonical_witnesses": [
                    {k: v for k, v in obs.items() if k != "oracle_wall_seconds"}
                    for obs in outcomes
                ],
            })
        return {
            "status": "PASS: all paired local witnesses matched frozen labels",
            "scope": "local development fixtures, canonical witnesses only",
            "case_count": len(records),
            "positive_count": sum(v for (p, positive), v in
                                  count_by_class.items() if positive),
            "negative_count": sum(v for (p, positive), v in
                                  count_by_class.items() if not positive),
            "family_counts": {
                prop: {"positive": count_by_class[(prop, True)],
                       "negative": count_by_class[(prop, False)]}
                for prop in PROPERTY_CLASSES
            },
            "public_manifest_sha256": self.public["public_manifest_sha256"],
            "verified": records,
        }
