"""D2.4B: source/ABI-only generic token property proposals for *real* OUSD.

The detector input is the pinned OUSD compiled ABI, not the upstream test
harness, historical bug labels, known-issues annotations or property traces.
This phase proposes two generic *metamorphic* properties and generates real
EVM checks. It does NOT claim new bugs, supply-change safety during rebases,
formal soundness, or improved stateful-fuzz recall.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from prism.defi_property_compiler import signatures

TEMPLATES = {
    "TRANSFER_SUPPLY_PRESERVED": {
        "required": ("balanceOf(address)", "totalSupply()", "transfer(address,uint256)"),
        "predicate": "With no mint/burn/rebase between observations, a successful ERC20 transfer leaves totalSupply unchanged.",
    },
    "APPROVE_ALLOWANCE_OVERWRITE": {
        "required": ("allowance(address,address)", "approve(address,uint256)"),
        "predicate": "A successful ERC20 approve overwrites allowance(owner,spender) with the supplied value.",
    },
}
FORBIDDEN = ("known_bugs", "canary", "exploit_trace", "variant_labels", "root_cause")


def select(abi: object) -> dict:
    names = signatures(abi)
    selected = []
    unknown = []
    for ident, spec in sorted(TEMPLATES.items()):
        missing = sorted(set(spec["required"]) - names)
        if missing:
            unknown.append({"id": ident, "decision": "UNKNOWN",
                            "missing": missing})
        else:
            selected.append({"id": ident, "decision": "CANDIDATE_UNVERIFIED",
                             "abi_dependencies":list(spec["required"]),
                             "predicate":spec["predicate"]})
    return {
        "schema":"prism-d24b-source-erc20-properties-v1",
        "source":"actual compiled Solidity ABI only",
        "candidates": selected,
        "unknown":unknown,
        "limitations":[
            "Manually-authored generic ERC20 templates, not a learned semantic property miner",
            "Does not identify vulnerability status from ABI shape",
            "Token supply conservation is scoped to one successful transfer without rebase/mint/burn",
            "No historical known-bug labels, upstream property names or EVM outcomes as input",
        ],
    }


def generated_solidity(selected: dict) -> str:
    if selected.get("schema")!="prism-d24b-source-erc20-properties-v1":
        raise ValueError("unrecognized source candidate set")
    permitted = set(TEMPLATES)
    ids = [x["id"] for x in selected["candidates"]]
    if len(ids)!=len(set(ids)) or not set(ids)<=permitted:
        raise ValueError("unknown or repeated generic property")
    if any(x.get("decision")!="CANDIDATE_UNVERIFIED" for x in selected["candidates"]):
        raise ValueError("a hypothesis was claimed verified before EVM")
    methods=[]
    if "TRANSFER_SUPPLY_PRESERVED" in ids:
        methods.append("""
    function testFuzz_PRISMTransferSupply(uint96 seed) public {
        tester.mint(0, 1000 ether);
        uint256 beforeSupply = asset.totalSupply();
        uint256 amount = uint256(seed) % (100 ether) + 1;
        vm.prank(address(0x30000));
        require(asset.transfer(address(0x40000), amount), "transfer-rejected");
        require(asset.totalSupply() == beforeSupply, "D24B_TRANSFER_SUPPLY_DRIFT");
    }
""")
    if "APPROVE_ALLOWANCE_OVERWRITE" in ids:
        methods.append("""
    function testFuzz_PRISMApproveOverwrite(uint96 seed) public {
        uint256 amount = uint256(seed);
        vm.prank(address(0x30000));
        require(asset.approve(address(0x40000), amount), "approve-rejected");
        require(asset.allowance(address(0x30000), address(0x40000)) == amount,
                "D24B_APPROVE_MISMATCH");
    }
""")
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24BAdapter, ID24BAsset} from "./D24BAdapter.sol";

// Generated from real compiled OUSD ABI, not from upstream labeled tests.
contract D24BGeneratedAssetTest is Test {
    D24BAdapter internal tester;
    ID24BAsset internal asset;
    function setUp() public {
        tester = new D24BAdapter();
        asset = ID24BAsset(tester.assetAddress());
    }
""" + "\n".join(methods) + "\n}\n"


def adapter_solidity() -> str:
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {CryticTester} from "./CryticTester.sol";

// Only an observation adapter: exact upstream OUSD code and deployment state.
contract D24BAdapter is CryticTester {
    function assetAddress() external view returns (address) {
        return address(ousd);
    }
}
interface ID24BAsset {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address,address) external view returns (uint256);
    function transfer(address,uint256) external returns (bool);
    function approve(address,uint256) external returns (bool);
}
"""


def build(abi_path:Path, out:Path, *, external_root:Path) -> dict:
    # No judge, known-bug manifest, public training comment, or fuzzer trace.
    if "judge" in str(abi_path).lower() or "bug" in str(abi_path).lower():
        raise ValueError("judge/label paths forbidden in detector compiler")
    raw=abi_path.read_bytes()
    abis=json.loads(raw)
    candidate=select(abis)
    testdir=external_root / "test" / "recon"
    if not (testdir / "CryticTester.sol").is_file():
        raise FileNotFoundError("pinned upstream CryticTester required")
    testdir.mkdir(parents=True,exist_ok=True)
    generated=testdir/"D24BGeneratedAsset.t.sol"
    adapter=testdir/"D24BAdapter.sol"
    generated.write_text(generated_solidity(candidate),encoding="utf-8")
    adapter.write_text(adapter_solidity(),encoding="utf-8")
    out.mkdir(parents=True,exist_ok=True)
    report={
        **candidate,
        "status":"CANDIDATES_GENERATED_NOT_VERIFIED",
        "abi_sha256":sha256(raw).hexdigest(),
        "generated_test_sha256":sha256(generated.read_bytes()).hexdigest(),
        "adapter_sha256":sha256(adapter.read_bytes()).hexdigest(),
        "candidate_count":len(candidate["candidates"]),
        "verified_vulnerabilities":None,
        "not_a_blind_holdout":True,
    }
    (out/"proposals.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("D24B_SOURCE_CANDIDATES",[x["id"] for x in candidate["candidates"]])
    print("D24B_UNKNOWN",candidate["unknown"])
    return report


if __name__ == "__main__":
    a=argparse.ArgumentParser()
    a.add_argument("--abi",type=Path,required=True)
    a.add_argument("--root",type=Path,required=True)
    a.add_argument("--output",type=Path,required=True)
    args=a.parse_args()
    build(args.abi.resolve(),args.output.resolve(),external_root=args.root.resolve())
