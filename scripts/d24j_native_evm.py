"""Isolated real-EVM observation of a D2.4J source-generated relation.

Compiles immutable public Uniswap V2 pair source and its pinned imports. The
fixture is a local Foundry project with fake tokens; no on-chain transactions,
vulnerability labels, historical exploit data, or fork RPC are used.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import posixpath
import re
import resource
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter

from prism.defi_blind_proposer import propose_relations
from scripts.d24j_label_free_trial import fetch_public_source, git_blob_digest


TESTS={
    "test_post_sync_reserves_reconcile_eight_external_mutations()",
    "test_external_balance_drift_is_observed_before_sync()",
    "test_post_sync_reconciles_burns_and_asymmetric_balances()",
}
SYNC_UPDATE=("_update(IERC20(token0).balanceOf(address(this)), "
             "IERC20(token1).balanceOf(address(this)), reserve0, reserve1);")
_IMPORT=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?['\"]([^'\"]+)['\"]\s*;")


def _native_rows(raw: str) -> dict:
    try:
        root=json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("native Foundry JSON unavailable") from exc
    if type(root) is not dict:
        raise ValueError("malformed Foundry JSON root")
    rows={}
    for suite in root.values():
        if type(suite) is not dict:
            continue
        tests=suite.get("test_results",{})
        if type(tests) is not dict:
            raise ValueError("bad native test inventory")
        for name,value in tests.items():
            if name in rows or type(value) is not dict:
                raise ValueError("duplicate/malformed native observation")
            rows[name]=value
    if set(rows)!=TESTS:
        raise ValueError("missing or unexpected independently executed native tests")
    return rows


def parse_foundry_lab(raw: str, exit_code: int) -> dict:
    rows=_native_rows(raw)
    if exit_code!=0 or any(rows[name].get("status")!="Success" for name in TESTS):
        raise ValueError("native read-after-write or negative control failed")
    return {"passed":len(TESTS),"total":len(TESTS),
            "native_test_names":sorted(rows),
            "native_stdout_sha256":sha256(raw.encode()).hexdigest()}


def parse_mutant_sensitivity(raw: str, exit_code: int) -> dict:
    """A deliberately no-op sync must be noticed by the same original oracle."""
    rows=_native_rows(raw)
    failures=sorted(name for name in TESTS if rows[name].get("status")=="Failure")
    if exit_code==0 or not failures or any(rows[name].get("status") not in ("Success","Failure")
                                          for name in TESTS):
        raise ValueError("native negative mutation escaped the invariant oracle")
    if "test_post_sync_reserves_reconcile_eight_external_mutations()" not in failures:
        raise ValueError("primary synchronization counterexample was not detected")
    return {"status":"DELIBERATE_LOCAL_MUTATION_DETECTED",
            "detected_failing_tests":failures,
            "native_stdout_sha256":sha256(raw.encode()).hexdigest(),
            "is_a_real_world_vulnerability":False}


def neutralize_sync_for_negative_control(source: str) -> str:
    if source.count(SYNC_UPDATE)!=1:
        raise ValueError("cannot construct isolated sync mutation without ambiguity")
    return source.replace(SYNC_UPDATE,"/* D24J isolated sensitivity control: no state update */",1)


def _relative_imports(path: str, data: bytes) -> list[str]:
    text=data.decode("utf-8",errors="strict")
    result=[]
    for relative in _IMPORT.findall(text):
        if not relative.startswith(".") or "://" in relative:
            raise ValueError("nonlocal Solidity import requires an unapproved dependency")
        target=posixpath.normpath(posixpath.join(posixpath.dirname(path),relative))
        if not target.startswith("contracts/") or not target.endswith(".sol"):
            raise ValueError("Solidity import escapes frozen repository contract tree")
        result.append(target)
    return result


def fetch_dependency_closure(main: dict) -> dict[str,bytes]:
    """Pin all files to the same immutable commit, never follow HEAD imports."""
    pending=[main["path"]]
    sources={}
    while pending:
        path=pending.pop()
        if path in sources:
            continue
        if len(sources)>=32:
            raise ValueError("dependency count exceeds bounded fixture")
        if path!=main["path"]:
            # Additional frozen-commit dependency blob digests are recorded
            # during the experiment; parent commit pins their identities.
            # fetch_public_source validates the main expected digest; for
            # dependencies fetch the fixed URL directly and check max bytes.
            from urllib.request import Request, urlopen
            url=("https://raw.githubusercontent.com/"+main["repository"]+"/"+
                 main["commit"]+"/"+path)
            with urlopen(Request(url,headers={"User-Agent":"PRISM-D24J-native-holdout"}),timeout=25) as response:
                data=response.read(1_000_001)
            if len(data)>1_000_000:
                raise ValueError("remote dependency exceeds source budget")
        else:
            data=fetch_public_source(main)
        sources[path]=data
        if sum(map(len,sources.values()))>500_000:
            raise ValueError("native source closure exceeds cumulative byte budget")
        pending.extend(_relative_imports(path,data))
    return sources


def run_native_evm(manifest: dict, source_root: Path, output: Path) -> dict:
    targets=[t for t in manifest["cohort"] if t["id"]=="C"]
    if len(targets)!=1 or targets[0]["repository"]!="Uniswap/v2-core":
        raise ValueError("only frozen C independent EVM observer is implemented")
    target=targets[0]
    sources=fetch_dependency_closure(target)
    pair_source=sources[target["path"]].decode("utf-8")
    proposal=propose_relations(pair_source,max_candidates=manifest["budgets"]["max_candidates_per_source"])
    expected="READ_AFTER_WRITE_RECONCILIATION:sync:_update:getReserves"
    if expected not in {c["identifier"] for c in proposal["candidates"]}:
        raise ValueError("source-generated EVM property not available; abstain")
    observer_source=(source_root/"benchmarks/defi/d24j/test/D24JReadAfterWrite.t.sol")
    output.mkdir(parents=True,exist_ok=True)
    t=perf_counter()
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    with TemporaryDirectory(prefix="prism-d24j-independent-evm-") as tmp:
        sandbox=Path(tmp)
        for path,content in sources.items():
            destination=sandbox/"src"/path.removeprefix("contracts/")
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(content)
        fixture=sandbox/"test"/observer_source.name
        fixture.parent.mkdir(parents=True,exist_ok=True)
        fixture.write_bytes(observer_source.read_bytes())
        (sandbox/"foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\n'
            'out = "out"\nlibs = []\nsolc_version = "0.5.16"\nffi = false\n'
            '[fuzz]\nruns = 16\n',encoding="utf-8")
        environment=dict(os.environ)
        environment.pop("ETH_RPC_URL",None)
        environment.pop("FOUNDRY_ETH_RPC_URL",None)
        command=["forge","test","--match-contract","D24JReadAfterWriteTest","--json"]
        try:
            process=subprocess.run(
                command,
                cwd=sandbox,env=environment,text=True,capture_output=True,
                timeout=180,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise RuntimeError("native EVM fixture unavailable or timed out") from exc
        # Inspect the passing primary trial BEFORE introducing a mutation.
        # Never let a failure of the primary source be reinterpreted as proof.
        checked=parse_foundry_lab(process.stdout,process.returncode)
        source_path=sandbox/"src"/target["path"].removeprefix("contracts/")
        original=source_path.read_text(encoding="utf-8")
        source_path.write_text(neutralize_sync_for_negative_control(original),encoding="utf-8")
        try:
            mutation=subprocess.run(command,cwd=sandbox,env=environment,
                                    text=True,capture_output=True,timeout=180,check=False)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise RuntimeError("mutated EVM oracle sensitivity run unavailable") from exc
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    (output/"native.stdout.json").write_text(process.stdout,encoding="utf-8")
    (output/"native.stderr.txt").write_text(process.stderr,encoding="utf-8")
    (output/"mutation.stdout.json").write_text(mutation.stdout,encoding="utf-8")
    (output/"mutation.stderr.txt").write_text(mutation.stderr,encoding="utf-8")
    sensitivity=parse_mutant_sensitivity(mutation.stdout,mutation.returncode)
    report={
        "schema":"scm.prism.d24j.native-evm-state-reconciliation.v1",
        "cohort_id":"C","source_sha256":sha256(sources[target["path"]]).hexdigest(),
        "main_source_git_blob_sha1":git_blob_digest(sources[target["path"]]),
        "all_dependency_git_blob_sha1":{k:git_blob_digest(v) for k,v in sorted(sources.items())},
        "hypothesis_identifier":expected,
        "observation_method":"independent_native_foundry_solidity_fixture",
        "negative_control":"pre-sync difference observed before reconciling",
        "native_test_result":checked,
        "deliberate_mutation_sensitivity":sensitivity,
        "wall_seconds":perf_counter()-t,
        "child_cpu_seconds":after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
        "ciel_actual_proposer_used":False,"confirmed_new_vulnerabilities":0,
        "status":"LOCAL_NATIVE_RELATION_OBSERVED_NOT_WHOLE_PROGRAM_SAFETY",
        "limitations":["Only one of three frozen projects received native EVM testing",
                       "Mutated transient sync is a labelled sensitivity control, not blind bug discovery",
                       "Three hand-authored semantic observer cases, not a blind dynamic oracle",
                       "Foundry verdicts rather than raw transaction state traces",
                       "A passing contract is not evidence that no other vulnerabilities exist"],
    }
    (output/"native-evaluation.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--preregistration",required=True,type=Path)
    p.add_argument("--root",default=Path("."),type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    manifest=json.loads(args.preregistration.read_text())
    report=run_native_evm(manifest,args.root.resolve(),args.out.resolve())
    print("D24J_NATIVE_EVM",json.dumps({
        "status":report["status"],"passed":report["native_test_result"]["passed"],
        "wall_seconds":round(report["wall_seconds"],3),"new_vulnerabilities":0},sort_keys=True))
