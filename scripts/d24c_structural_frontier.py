"""D2.4C: bounded, source-visible dependency frontier diagnostic on actual OUSD.

Not a Solidity parser, sound program slicer, auto property generator, or bug
finder. It is a measured first SCM component: only extract reachable function
bodies relevant to a *researcher-supplied* property specification, preserving
all unresolved/external semantics as uncertainty. Never claim omitted code safe.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re

IDENT = re.compile(r"[A-Za-z_]\w*")
FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# Goal anchoring is EXPLICIT, not learnt. It reflects conventional token specs.
GOALS = {
    "ALLOWANCE_DEBIT": {"roots": ("transferFrom", "approve", "allowance"),
                        "symbols": ("allowances",)},
    "SUPPLY_TRANSITIONS": {"roots": ("transfer", "transferFrom", "mint",
                                    "burn", "changeSupply"),
                           "symbols": ("totalSupply", "nonRebasingSupply",
                                       "rebasingCredits_")},
}
ALLOWANCE_WITNESS = "allowances[_from][msg.sender] = userAllowance - _value;"


def mask_noncode(text: str) -> str:
    """Preserve offsets and line breaks while masking comments and strings.

    Deliberately conservative: does not parse preprocessor/inherited semantics.
    """
    out = list(text)
    state = "code"
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if a == "/" and b == "/":
                out[i] = out[i + 1] = " "
                state = "line"
                i += 2
                continue
            if a == "/" and b == "*":
                out[i] = out[i + 1] = " "
                state = "block"
                i += 2
                continue
            if a in ("'", '"'):
                out[i] = " "
                state = a
            i += 1
            continue
        if state == "line":
            if a == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue
        if state == "block":
            if a == "*" and b == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
            else:
                if a != "\n":
                    out[i] = " "
                i += 1
            continue
        if a == "\\" and i + 1 < len(text):
            out[i] = out[i + 1] = " "
            i += 2
            continue
        if a == state:
            out[i] = " "
            state = "code"
        elif a != "\n":
            out[i] = " "
        i += 1
    if state not in ("code", "line"):
        raise ValueError("unterminated source comment/string")
    return "".join(out)


def extract_functions(source: str) -> dict[str, tuple[int, int, str]]:
    clean = mask_noncode(source)
    result = {}
    for match in FUNCTION.finditer(clean):
        name = match.group(1)
        if name in result:
            raise ValueError("overloaded names unsupported; UNKNOWN")
        # Opening body occurs after complete signature/modifiers/return types.
        depth = 1
        i = match.end()
        while i < len(clean) and depth:
            if clean[i] == "(":
                depth += 1
            elif clean[i] == ")":
                depth -= 1
            i += 1
        if depth:
            raise ValueError(f"malformed function signature: {name}")
        while i < len(clean) and clean[i] not in "{;":
            i += 1
        if i >= len(clean):
            raise ValueError(f"unterminated function declaration: {name}")
        if clean[i] == ";":
            continue  # Declaration without body is not a local implementation.
        opening = i
        braces = 1
        i += 1
        while i < len(clean) and braces:
            if clean[i] == "{":
                braces += 1
            elif clean[i] == "}":
                braces -= 1
            i += 1
        if braces:
            raise ValueError(f"unterminated function body: {name}")
        result[name] = (opening, i, clean[opening:i])
    if not result:
        raise ValueError("no implemented functions")
    return result


def frontier(source: str, goals: dict = GOALS) -> dict:
    clean = mask_noncode(source)
    functions = extract_functions(source)
    names = set(functions)
    entries = {}
    for name, (lo, hi, body) in functions.items():
        called = {x for x in CALL.findall(body) if x in names}
        symbols = set(IDENT.findall(body))
        # Member calls and inherited or external functions remain UNKNOWN.
        dotted = sorted(set(re.findall(
            r"\b[A-Za-z_]\w*\s*\.\s*([A-Za-z_]\w*)\s*\(",
            body)))
        entries[name] = {"calls": sorted(called), "symbols": symbols,
                         "span": (lo, hi), "external_or_member_calls": dotted}
    result = {"schema": "scm-d24c-dependency-frontier-v1",
              "source_sha256": sha256(source.encode()).hexdigest(),
              "status": "STRUCTURAL_DIAGNOSTIC_NOT_SECURITY_PROOF",
              "function_count": len(functions), "goals": {},
              "limitations": ["Manual roots and state symbols",
                              "Approximate lexical call graph; overloaded/inherited semantics UNKNOWN",
                              "No evaluation of branch conditions, dynamic dispatch or EVM state",
                              "Smaller textual frontier does not imply lower end-to-end cost",
                              "No independent bug discovery or scientific superiority"]}
    for goal, spec in sorted(goals.items()):
        roots = tuple(spec["roots"])
        if not set(roots) <= names:
            raise ValueError(f"missing required goal entrypoint {goal}")
        closure = set(roots)
        queue = list(roots)
        while queue:
            name = queue.pop()
            for child in entries[name]["calls"]:
                if child not in closure:
                    closure.add(child)
                    queue.append(child)
        referenced = sorted(n for n in closure
                            if set(spec["symbols"]) & entries[n]["symbols"])
        unresolved = sorted({call for n in closure
                             for call in entries[n]["external_or_member_calls"]})
        if not referenced:
            raise ValueError(f"no observable goal-symbol dependency for {goal}")
        report = {"roots": list(roots), "function_frontier": sorted(closure),
                  "selected_functions": len(closure),
                  "all_functions": len(functions),
                  "function_count_reduction_fraction":
                      (len(functions)-len(closure))/len(functions),
                  "property_symbols_seen": referenced,
                  "unresolved_member_calls": unresolved,
                  "unknown_semantics": bool(unresolved),
                  "full_source_remains_required_for_sound_security_claim": True}
        result["goals"][goal] = report

    # A regression known FROM SOURCE is a control only. Never count as bug discovery.
    # The precise allowance debit statement was observed independently in D2.4C.
    loc = clean.find(ALLOWANCE_WITNESS)
    if loc >= 0 and "ALLOWANCE_DEBIT" in result["goals"]:
        fn = [name for name,(lo,hi,_) in functions.items() if lo <= loc < hi]
        result["allowance_known_witness_in_frontier"] = (
            len(fn) == 1 and fn[0] in result["goals"]["ALLOWANCE_DEBIT"]["function_frontier"])
    else:
        result["allowance_known_witness_in_frontier"] = None
    return result


def evaluate(source_file: Path, output: Path) -> dict:
    raw = source_file.read_text(encoding="utf-8")
    record = frontier(raw)
    if record["allowance_known_witness_in_frontier"] is not True:
        raise ValueError("positive-control witness missing from declared decision frontier")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    for name, entry in record["goals"].items():
        print("D24C_FRONTIER",name,"selected",entry["selected_functions"],
              "total",entry["all_functions"],
              "unknown_external_calls",len(entry["unresolved_member_calls"]))
    print("D24C_FRONTIER_WITNESS",record["allowance_known_witness_in_frontier"])
    return record


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    evaluate(args.source, args.out)
