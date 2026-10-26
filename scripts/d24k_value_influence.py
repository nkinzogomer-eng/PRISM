"""Independent EVM cash-flow witness on untouched pinned Solmate ERC4626.

The laboratory scenario is a KNOWN first-depositor exchange-rate manipulation
when an application allows deposits without a minimum-share/slippage guard.
It is not a new vulnerability class, exploit of live funds, or a zero-day.
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
from urllib.request import Request, urlopen

from prism.d24k_structural import propose_value_influence
from scripts.d24j_label_free_trial import fetch_public_source,git_blob_digest


TESTS={
    "test_native_donation_changes_price_without_minting_shares()",
    "test_native_unprotected_victim_loss_and_attacker_profit()",
    "test_native_undonated_control_has_no_victim_loss()",
    "test_native_minimum_share_guard_refuses_dilution()",
}
IMPORT=re.compile(r"\bimport\s+(?:[^;]*?\s+from\s+)?['\"]([^'\"]+)['\"]\s*;")


def check_native_trial(raw: str, exit_code: int) -> dict:
    try:
        root=json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("real EVM outcome JSON missing or invalid") from exc
    if type(root) is not dict:
        raise ValueError("wrong EVM root structure")
    rows={}
    for suite in root.values():
        if type(suite) is not dict:
            continue
        for name,entry in suite.get("test_results",{}).items():
            if name in rows or type(entry) is not dict:
                raise ValueError("duplicated or malformed native oracle result")
            rows[name]=entry
    if set(rows)!=TESTS:
        raise ValueError("incomplete economic EVM controls; cannot count partial evidence")
    if exit_code!=0 or any(rows[name].get("status")!="Success" for name in TESTS):
        raise ValueError("native economic value-transfer/negative-control witness failed")
    return {"passed":len(TESTS),"total":len(TESTS),
            "test_names":sorted(TESTS),"stdout_sha256":sha256(raw.encode()).hexdigest()}


def _dependencies(main: dict) -> dict[str,bytes]:
    pending=[main["path"]]
    found={}
    while pending:
        path=pending.pop()
        if path in found:
            continue
        if len(found)>=20:
            raise ValueError("unexpectedly large pinned source closure")
        if path==main["path"]:
            data=fetch_public_source(main)
        else:
            url=("https://raw.githubusercontent.com/"+main["repository"]+"/"+
                 main["commit"]+"/"+path)
            with urlopen(Request(url,headers={"User-Agent":"PRISM-local-ERC4626-research"}),
                         timeout=25) as response:
                data=response.read(500_001)
        if len(data)>500_000 or not data:
            raise ValueError("unbounded/invalid source dependency")
        found[path]=data
        for imp in IMPORT.findall(data.decode("utf-8")):
            if not imp.startswith("."):
                raise ValueError("only pinned local Solidity imports allowed")
            imported=posixpath.normpath(posixpath.join(posixpath.dirname(path),imp))
            if not imported.startswith("src/") or not imported.endswith(".sol"):
                raise ValueError("source dependency escapes frozen tree")
            pending.append(imported)
    if sum(map(len,found.values()))>500_000:
        raise ValueError("sum of Solidity dependencies exceeds budget")
    return found


def run_value_trial(manifest: dict,root: Path,output: Path) -> dict:
    selected=[t for t in manifest["cohort"] if t.get("id")=="A"]
    if len(selected)!=1 or selected[0]["repository"]!="transmissions11/solmate":
        raise ValueError("approved pinned source A missing")
    target=selected[0]
    fixture=root/"benchmarks/defi/d24j/test/D24JValueInfluence.t.sol"
    if not fixture.is_file():
        raise ValueError("independently authored local economic observer missing")
    sources=_dependencies(target)
    # This work queue is automatically derived from the original source,
    # before native EVM execution. The verifier is separate authored code.
    proposed=propose_value_influence(sources[target["path"]].decode("utf-8"))
    candidate_id="asset_share_rate:donation_without_share_issuance"
    matches=[item for item in proposed["candidates"] if item["identifier"]==candidate_id]
    if len(matches)!=1:
        raise ValueError("structural economic hypothesis not derivable: UNKNOWN")
    output.mkdir(parents=True,exist_ok=True)
    started=perf_counter()
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    with TemporaryDirectory(prefix="prism-solmate-value-oracle-") as workspace:
        ephemeral=Path(workspace)
        for rel,content in sources.items():
            path=ephemeral/"src"/rel.removeprefix("src/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(content)
        testfile=ephemeral/"test"/fixture.name
        testfile.parent.mkdir(parents=True,exist_ok=True)
        testfile.write_bytes(fixture.read_bytes())
        (ephemeral/"foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\n'
            'out = "out"\nlibs = []\nsolc_version = "0.8.24"\nffi = false\n',
            encoding="utf-8")
        env=dict(os.environ)
        env.pop("ETH_RPC_URL",None)
        env.pop("FOUNDRY_ETH_RPC_URL",None)
        native=subprocess.run(["forge","test","--match-contract","D24JValueInfluenceTest","--json"],
                     cwd=ephemeral,env=env,text=True,capture_output=True,
                     timeout=180,check=False)
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    (output/"economic.stdout.json").write_text(native.stdout,encoding="utf-8")
    (output/"economic.stderr.txt").write_text(native.stderr,encoding="utf-8")
    verified=check_native_trial(native.stdout,native.returncode)
    outcome={
        "schema":"scm.prism.d24k.erc4626-value-influence-observation.v1",
        "source_repository":target["repository"],"pinned_commit":target["commit"],
        "original_source_sha256":sha256(sources[target["path"]]).hexdigest(),
        "source_closure_git_blob_sha1":{k:git_blob_digest(v) for k,v in sorted(sources.items())},
        "proposer_schema":proposed["schema"],
        "derived_hypothesis":matches[0],
        "source_first_inference":"DETERMINISTIC_PROPOSE_THEN_SEPARATE_EVM_ORACLE",
        "hypothesis_was_developed_using_this_source":True,
        "native_observation":verified,
        "units_in_local_scenario":{"attacker_upfront_assets":101,"victim_deposit_assets":199,
                                   "attacker_redeemed_assets":150,"victim_redeemed_assets":150,
                                   "attacker_gain":49,"victim_loss":49},
        "semantic_scope":"local unprotected ERC4626 vault with direct asset donation and no minimum-share guard",
        "counterfactual_without_donation_has_no_loss":True,
        "slippage_guard_defeats_this_local_scenario":True,
        "known_public_attack_family":"ERC4626_exchange_rate_inflation_and_rounding",
        "is_new_vulnerability_class":False,
        "is_zero_day":False,
        "deployment_specific_severity":"NOT_ASSESSED",
        "child_cpu_seconds":after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
        "wall_seconds":perf_counter()-started,
        "no_real_chain_or_funds":True,
        "status":"KNOWN_ECONOMIC_BEHAVIOR_REPRODUCED_ON_REAL_SOURCE_NOT_ZERO_DAY",
    }
    (output/"economic-evidence.json").write_text(json.dumps(outcome,indent=2,sort_keys=True)+"\n")
    return outcome


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--preregistration",required=True,type=Path)
    p.add_argument("--root",type=Path,default=Path("."))
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    manifest=json.loads(args.preregistration.read_text())
    result=run_value_trial(manifest,args.root.resolve(),args.out.resolve())
    print("D24K_REAL_SOURCE_VALUE",json.dumps({
        "status":result["status"],"tests":result["native_observation"]["passed"],
        "attacker_gain":49,"victim_loss":49,"new_zero_day":False,
        "seconds":round(result["wall_seconds"],4)},sort_keys=True))
