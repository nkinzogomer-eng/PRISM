"""D2.4L compiler AST + native EVM laboratory positive/negative controls.

The bank example is intentionally known and synthetic. Pinned original Solmate
sources are compiled alongside as a real-world parser stressor, not claimed
to be the source of the synthetic reentrancy finding.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter

from prism.d24l_typed_graph import typed_graph
from scripts.d24k_value_influence import _dependencies
from scripts.d24j_label_free_trial import git_blob_digest


TESTS = {
    "test_vulnerable_bank_yields_independent_evm_reentrancy_witness()",
    "test_same_actor_cannot_profit_against_update_before_call()",
    "test_without_attacker_the_unsafe_bank_can_withdraw_normally()",
}


def verify_native_evm(output: str, code: int) -> dict:
    try:
        value=json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError("native test result was not JSON") from exc
    rows={}
    if type(value) is not dict:
        raise ValueError("malformed native result")
    for suite in value.values():
        if not isinstance(suite, dict):
            continue
        for name, test in suite.get("test_results", {}).items():
            if name in rows or not isinstance(test, dict):
                raise ValueError("repeated or malformed test")
            rows[name]=test
    if set(rows)!=TESTS or code!=0 or any(row.get("status")!="Success" for row in rows.values()):
        raise ValueError("laboratory EVM controls incomplete or failed")
    return {"tests_passed": len(rows), "tests_total": len(TESTS),
            "oracle_stdout_sha256": sha256(output.encode()).hexdigest()}


def select_build_info(path: Path) -> dict:
    found=[]
    for item in sorted(path.glob("*.json")):
        root=json.loads(item.read_text())
        sources=root.get("output", {}).get("sources", {})
        if (any(x.endswith("D24LBankValue.t.sol") for x in sources) and
            any(x.endswith("ERC4626.sol") for x in sources)):
            found.append(root)
    if len(found)!=1:
        raise ValueError("expected exactly one complete typed compiler build with real original contract")
    return found[0]


def _command(argv: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    environment=dict(os.environ)
    environment.pop("ETH_RPC_URL",None)
    environment.pop("FOUNDRY_ETH_RPC_URL",None)
    return subprocess.run(argv,cwd=cwd,env=environment,text=True,capture_output=True,
                          check=False,timeout=timeout)


def run_trial(registration: dict, project: Path, out: Path) -> dict:
    eligible=[x for x in registration["cohort"] if x.get("id")=="A"]
    if len(eligible)!=1 or eligible[0]["repository"]!="transmissions11/solmate":
        raise ValueError("approved original pinned Solidity source unavailable")
    source_root=eligible[0]
    external_sources=_dependencies(source_root)
    fixture_bank=project/"benchmarks/defi/d24j/test/D24LBankValue.t.sol"
    fixture_real=project/"benchmarks/defi/d24j/test/D24JValueInfluence.t.sol"
    if not fixture_bank.is_file() or not fixture_real.is_file():
        raise ValueError("independently authored test fixture missing")
    out.mkdir(parents=True,exist_ok=True)
    start=perf_counter()
    cpu_start=resource.getrusage(resource.RUSAGE_CHILDREN)
    with TemporaryDirectory(prefix="prism-d24l-typed-ast-native-") as directory:
        temp=Path(directory)
        for file,data in external_sources.items():
            local=temp/file
            local.parent.mkdir(parents=True,exist_ok=True)
            local.write_bytes(data)
        tests=temp/"test"
        tests.mkdir()
        for file in (fixture_bank,fixture_real):
            (tests/file.name).write_bytes(file.read_bytes())
        (temp/"foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
            'libs = []\nsolc_version = "0.8.24"\nffi = false\n'
            'build_info = true\n',encoding="utf-8")
        build=_command(["forge","build","--force","--build-info","--ast"],temp,240)
        (out/"compiler.stdout.txt").write_text(build.stdout[-30_000:],encoding="utf-8")
        (out/"compiler.stderr.txt").write_text(build.stderr[-30_000:],encoding="utf-8")
        if build.returncode:
            raise ValueError("pinned compiler rejected actual source + local control fixture")
        info=select_build_info(temp/"out/build-info")
        compiled=info["output"]
        graph=typed_graph(compiled)
        (out/"typed-graph.json").write_text(json.dumps(graph,indent=2,sort_keys=True)+"\n")
        unsafe=[x for x in graph["candidates"] if x["contract"]=="D24LUnsafeBank"
                and x["signature"].startswith("withdraw(")]
        guarded=[x for x in graph["candidates"] if x["contract"]=="D24LGuardedBank"
                 and x["signature"].startswith("withdraw(")]
        if len(unsafe)!=1 or guarded:
            raise ValueError("frozen synthetic typed recognition failed: " + json.dumps({
                "unsafe":unsafe,"guarded":guarded,
                "bank_withdraw_functions":[r for r in graph["functions"]
                  if r["contract"] in {"D24LUnsafeBank","D24LGuardedBank"}
                  and r["signature"].startswith("withdraw(")]},sort_keys=True)[:12000])
        native=_command(["forge","test","--match-contract","D24LBankValueTest","--json"],
                        temp,240)
        (out/"native.stdout.json").write_text(native.stdout)
        (out/"native.stderr.txt").write_text(native.stderr)
        verified=verify_native_evm(native.stdout,native.returncode)
    cpu_end=resource.getrusage(resource.RUSAGE_CHILDREN)
    data={
        "schema":"scm.prism.d24l.compiler-state-call-local-witness.v1",
        "compiler_version":info.get("solcVersion","UNKNOWN"),
        "published_real_source_repository":source_root["repository"],
        "published_real_source_commit":source_root["commit"],
        "original_source_closure_git_sha1":{name:git_blob_digest(src) for name,src
                                            in sorted(external_sources.items())},
        "fixture_hash":sha256(fixture_bank.read_bytes()).hexdigest(),
        "compiler_build_contains_source_ast":True,
        "real_source_is_not_reentrancy_finding":True,
        "synthetic_vulnerable_candidate_count":len(unsafe),
        "synthetic_fixed_candidate_count":len(guarded),
        "graph_contract_count":graph["contract_count"],
        "graph_function_count":graph["function_count"],
        "graph_unsupported_functions":graph["unsupported_function_count"],
        "graph_total_unverified_candidates":len(graph["candidates"]),
        "native_oracle":verified,
        "known_attack_family":"REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_UPDATE",
        "positive_control_stolen_ether":"1 ether from benign depositor",
        "negative_control_stolen_ether":"0 ether",
        "novel_vulnerabilities_confirmed":0,
        "zero_days_confirmed":0,
        "baseline_run":False,
        "machine_normalized_performance_comparison":False,
        "child_cpu_seconds":cpu_end.ru_utime+cpu_end.ru_stime-cpu_start.ru_utime-cpu_start.ru_stime,
        "wall_seconds":perf_counter()-start,
        "outcome":"COMPILER_TYPED_SYNTHETIC_CONTROL_ONLY_NO_NOVEL_VULNERABILITY",
    }
    (out/"evidence.json").write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    return data


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--preregistration",type=Path,required=True)
    parser.add_argument("--root",type=Path,default=Path("."))
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    evidence=run_trial(json.loads(args.preregistration.read_text()),
                       args.root.resolve(),args.out.resolve())
    print("D24L_TYPED_GATE",json.dumps({
        "native":evidence["native_oracle"]["tests_passed"],
        "contracts":evidence["graph_contract_count"],
        "functions":evidence["graph_function_count"],
        "unsafe":evidence["synthetic_vulnerable_candidate_count"],
        "fixed":evidence["synthetic_fixed_candidate_count"],
        "novel":0,"zero_days":0,"seconds":round(evidence["wall_seconds"],4)
    },sort_keys=True))
