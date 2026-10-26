"""D2.4J label-free DeFi relational hypothesis proposer.

Only frozen source text and an explicit candidate budget are used. This
derives *new verification obligations*, NOT new vulnerability classes or
evidence of failure. Solidity imports, inheritance, semantics, and execution
are unresolved until an independent native-EVM verifier is attached.
"""
from __future__ import annotations

from hashlib import sha256
import re

from scripts.d24c_structural_frontier import extract_functions


_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)")


def propose_relations(source: str, *, max_candidates: int = 20) -> dict:
    """Propose cross-operation consistency obligations, without bug labels.

    An empty list never means safe. All candidates require external semantic
    review and evidence; only lexical patterns are used here.
    """
    if type(source) is not str or not source.strip() or len(source.encode()) > 1_000_000:
        raise ValueError("unbounded or missing source")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 64:
        raise ValueError("invalid candidate budget")
    functions = extract_functions(source)  # reject syntactic ambiguity, do not guess
    names = set(functions)
    proposals = []

    def append(*, family: str, operations: list[str], observer: str,
               statement: str, assumptions: list[str], signals: list[str]):
        proposals.append({
            "identifier":f"{family}:{':'.join(operations)}",
            "family":family,
            "operations":operations,
            "source_signals":sorted(set(signals)),
            "candidate_property":statement,
            "independent_trace_requirements":observer,
            "semantic_assumptions":assumptions,
            "status":"UNVERIFIED_REQUIRES_INDEPENDENT_EVM",
        })

    # Derive a relation from two matching method shapes rather than a
    # programmer-supplied vulnerability label or expected mutant.
    for name in sorted(names):
        if not name.startswith("preview") or len(name) <= len("preview"):
            continue
        stem=name[len("preview"):]
        operation=stem[0].lower()+stem[1:]
        if operation not in names:
            continue
        append(family="PREVIEW_TRANSITION_RELATION",operations=[name,operation],
            observer="Pre-state quote plus actual asset/share changes after isolated EVM call",
            statement="A pre-state quote and its matching transition should reconcile according to protocol fees and rounding",
            assumptions=["Quotes are valid in same initial state", "Fees and rounding semantics require an external specification"],
            signals=[name,operation])

    converters=sorted(n for n in names if n.startswith("convertTo") and len(n)>9)
    if len(converters)==2:
        for first,second in ((converters[0],converters[1]),
                             (converters[1],converters[0])):
            append(family="ROUND_TRIP_NONEXPANSION",operations=[first,second],
                observer="Evaluate the two real view functions on the same local EVM state and bounded input",
                statement="Two downward-rounded inverse unit conversions should not increase the original quantity",
                assumptions=["Functions convert inverse units", "Both functions round downward", "Valid input does not revert"],
                signals=converters)

    # Synthesize read-after-write obligations by matching state names in an
    # accessor body to LHS writes in an internal transition; no ABI labels.
    for reader in sorted(name for name in names if name.startswith("get")):
        read_tokens=set(_IDENT.findall(functions[reader][2]))
        for updater in sorted(name for name in names if name.startswith("_") and "update" in name.lower()):
            changed=set(_ASSIGN.findall(functions[updater][2]))
            common=sorted(read_tokens & changed)
            if not common:
                continue
            for entrypoint in sorted(names-{reader,updater}):
                body=functions[entrypoint][2]
                if re.search(r"\b"+re.escape(updater)+r"\s*\(",body) is None:
                    continue
                append(family="READ_AFTER_WRITE_RECONCILIATION",
                    operations=[entrypoint,updater,reader],
                    observer="Capture native-EVM before/after accessor results, transition calls and state deltas",
                    statement="An accepted transition invoking its state updater should reconcile subsequent accessor values with the updated state",
                    assumptions=["Getter and updater refer to the same storage under local EVM semantics",
                                 "Intermediate calls or hooks may affect the state"],
                    signals=common)

    proposals.sort(key=lambda p:p["identifier"])
    original=len(proposals)
    chosen=proposals[:max_candidates]
    return {
        "schema":"scm.prism.d24j.label-free-relational-hypotheses.v1",
        "source_sha256":sha256(source.encode()).hexdigest(),
        "function_count":len(functions),
        "method":"bounded_source_only_structural_relation_grammar",
        "candidates":chosen,
        "generated_before_budget":original,
        "omitted_for_budget":original-len(chosen),
        "semantic_verification":"NOT_ATTEMPTED",
        "native_evm_traces_observed":0,
        "confirmed_vulnerabilities":0,
        "confirmed_new_vulnerability_families":0,
        "no_candidates_means_safe":False,
        "limitations":[
            "Syntactic lexical extractor is not a sound Solidity AST or EVM model",
            "No import, inheritance, modifier, assembly or economic semantics resolved",
            "A plausible relation can be false or inapplicable due to fees or hooks",
            "All observations and security adjudications require an independent oracle",
        ],
    }
