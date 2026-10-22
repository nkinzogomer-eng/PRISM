"""D1.0 development-only vulnerability/property corpus.

Each pair is a local, self-contained Python example. Code is generated without
descriptive "vulnerable", "fixed", or "safe" tokens in names/contents. Ground
truth is stored in a separate oracle.json, but remains accessible in the repo.
This is NOT a blind holdout, natural prevalence estimate, or real-world dataset.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import textwrap

VERSION = "d10-development-v1"
SQLI_PAYLOADS = (
    "' OR 1=1 -- ",
    "' UNION SELECT owner FROM records -- ",
)
BAC_WITNESS = {"principal": "alice", "record_key": "b-doc"}


@dataclass(frozen=True)
class Pair:
    pair_id: str
    property_id: str
    version_one: str
    version_two: str


SQL_PAIRS = (
    Pair("q01", "SQLI_UNEXPECTED_OWNER",
         """query = f"SELECT owner FROM records WHERE owner = '{supplied}'"
return [r[0] for r in conn.execute(query)]""",
         """query = "SELECT owner FROM records WHERE owner = ?"
return [r[0] for r in conn.execute(query, (supplied,))]"""),
    Pair("q02", "SQLI_UNEXPECTED_OWNER",
         """where = "owner='" + supplied + "'"
sql = "SELECT owner FROM records WHERE " + where
return [r[0] for r in conn.execute(sql)]""",
         """sql = "SELECT owner FROM records WHERE owner = :name"
return [r[0] for r in conn.execute(sql, {"name": supplied})]"""),
    Pair("q03", "SQLI_UNEXPECTED_OWNER",
         """sql = "SELECT owner FROM records WHERE owner = '{}'".format(supplied)
return [r[0] for r in conn.execute(sql)]""",
         """escaped = supplied.replace("'", "''")
sql = "SELECT owner FROM records WHERE owner = '{}'".format(escaped)
return [r[0] for r in conn.execute(sql)]"""),
    Pair("q04", "SQLI_UNEXPECTED_OWNER",
         """def clause(value):
    return "owner='" + value + "'"
statement = "SELECT owner FROM records WHERE " + clause(supplied)
return [r[0] for r in conn.execute(statement)]""",
         """if not supplied.isascii() or not supplied.isalpha() or len(supplied) > 16:
    return []
statement = f"SELECT owner FROM records WHERE owner='{supplied}'"
return [r[0] for r in conn.execute(statement)]"""),
    Pair("q05", "SQLI_UNEXPECTED_OWNER",
         """value = supplied.strip()
statement = "SELECT owner FROM records WHERE owner='%s'" % value
return [r[0] for r in conn.execute(statement)]""",
         """if supplied not in {"alice", "bob"}:
    return []
statement = "SELECT owner FROM records WHERE owner='%s'" % supplied
return [r[0] for r in conn.execute(statement)]"""),
    Pair("q06", "SQLI_UNEXPECTED_OWNER",
         """def prepare(name):
    return ["SELECT owner", "FROM records", f"WHERE owner='{name}'"]
statement = " ".join(prepare(supplied))
return [r[0] for r in conn.execute(statement)]""",
         """def prepare(name):
    return ("SELECT owner FROM records WHERE owner=?", (name,))
statement, parameters = prepare(supplied)
return [r[0] for r in conn.execute(statement, parameters)]"""),
)

BAC_PAIRS = (
    Pair("a01", "BAC_CROSS_TENANT_READ",
         """item = records.get(record_key)
return item["value"] if item else None""",
         """item = records.get(record_key)
if item is None or item["owner"] != principal:
    return None
return item["value"]"""),
    Pair("a02", "BAC_CROSS_TENANT_READ",
         """if principal not in {"alice", "bob"}:
    return None
item = records.get(record_key)
return item["value"] if item else None""",
         """if principal not in {"alice", "bob"}:
    return None
item = records.get(record_key)
return item["value"] if item and item["owner"] == principal else None"""),
    Pair("a03", "BAC_CROSS_TENANT_READ",
         """def find_item(index, key):
    return index.get(key)
item = find_item(records, record_key)
return None if item is None else item["value"]""",
         """def find_item(index, key):
    return index.get(key)
item = find_item(records, record_key)
return item["value"] if item is not None and item["owner"] == principal else None"""),
    Pair("a04", "BAC_CROSS_TENANT_READ",
         """if record_key not in records:
    return None
return records[record_key].get("value")""",
         """if record_key not in records:
    return None
item = records[record_key]
if item.get("owner") != principal:
    return None
return item.get("value")"""),
    Pair("a05", "BAC_CROSS_TENANT_READ",
         """lookup = records.get
item = lookup(record_key)
if not item:
    return None
return item["value"]""",
         """lookup = records.get
item = lookup(record_key)
if not item or item.get("owner") != principal:
    return None
return item["value"]"""),
    Pair("a06", "BAC_CROSS_TENANT_READ",
         """def accepted(actor):
    return actor == "alice" or actor == "bob"
if not accepted(principal):
    return None
item = records.get(record_key)
return item["value"] if item else None""",
         """def accepted(actor, item):
    return item is not None and item.get("owner") == actor
item = records.get(record_key)
if not accepted(principal, item):
    return None
return item["value"]"""),
)

PAIRS = SQL_PAIRS + BAC_PAIRS


def positive_letter(pair_id: str) -> str:
    """Stable balanced assignment of the two functional variants to neutral IDs."""
    return "a" if int(hashlib.sha256(pair_id.encode()).hexdigest(), 16) % 2 else "b"


def source_for(pair: Pair, body: str) -> bytes:
    if pair.property_id == "SQLI_UNEXPECTED_OWNER":
        signature = "def run(conn, supplied):"
    elif pair.property_id == "BAC_CROSS_TENANT_READ":
        signature = "def run(records, principal, record_key):"
    else:
        raise ValueError("unknown property")
    code = signature + "\n" + textwrap.indent(textwrap.dedent(body).strip(), "    ") + "\n"
    compile(code, pair.pair_id + ".py", "exec")
    return code.encode("utf-8")


def generate() -> list[tuple[dict, dict, bytes]]:
    """Return public case metadata, oracle-only metadata and pinned file bytes."""
    cases = []
    for pair in PAIRS:
        a_is_positive = positive_letter(pair.pair_id) == "a"
        for letter in ("a", "b"):
            positive = (letter == "a") == a_is_positive
            case_id = pair.pair_id + letter
            body = pair.version_one if positive else pair.version_two
            raw = source_for(pair, body)
            public = {
                "case_id": case_id,
                "pair_id": pair.pair_id,
                "property_id": pair.property_id,
                "path": "cases/" + case_id + ".py",
                "entrypoint": "run",
                "source_sha256": hashlib.sha256(raw).hexdigest(),
            }
            oracle = {
                "case_id": case_id,
                "ground_truth": "vulnerable" if positive else "patched",
                "property_id": pair.property_id,
                "witnesses": ([{"supplied": p} for p in SQLI_PAYLOADS] if
                              pair.property_id == "SQLI_UNEXPECTED_OWNER" else
                              [dict(BAC_WITNESS)]),
                "severity": "unrated",
            }
            cases.append((public, oracle, raw))
    return sorted(cases, key=lambda item: item[0]["case_id"])
