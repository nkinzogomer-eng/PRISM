"""D2.4C economic multi-step hypotheses from external compiled OUSD ABI only.

These are MANUALLY designed ERC20/rebasing patterns, not mined semantic laws.
Never import benchmark known-bug labels or test-name catalog into candidate selection.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
from prism.defi_property_compiler import signatures

SPECS = {
    "NONREBASING_HOLDER_ISOLATION": (
        "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
        "rebaseOptOut()", "rebaseOptIn()", "changeSupply(uint256)", "vaultAddress()", "nonRebasingSupply()"
    ),
    "SPENDER_ALLOWANCE_DEBIT": (
        "balanceOf(address)", "approve(address,uint256)",
        "allowance(address,address)", "transferFrom(address,address,uint256)"
    ),
}

def choose(abi: object) -> dict:
    known = signatures(abi)
    candidates, unknown = [], []
    for ident, required in sorted(SPECS.items()):
        missing = sorted(set(required) - known)
        if missing:
            unknown.append({"id":ident,"status":"UNKNOWN","missing":missing})
        else:
            candidates.append({"id":ident,"status":"HYPOTHESIS_NOT_VERIFIED",
                               "requires":list(required)})
    return {"schema":"prism-d24c-economic-v1", "input":"external compiled ABI only",
            "candidates":candidates,"unknown":unknown,
            "source_code_semantics_inferred":False,
            "historical_root_causes":None,
            "limitations":["Manual token/rebasing templates, not general semantic inference",
                           "ABI presence does not imply safe behavior or reachable state",
                           "Public benchmark is not an unseen holdout"]}

def solidity(proposals: dict) -> str:
    if proposals.get("schema") != "prism-d24c-economic-v1":
        raise ValueError("wrong schema")
    ids = [x["id"] for x in proposals["candidates"]]
    if set(ids)!=set(SPECS) or len(ids)!=len(SPECS):
        raise ValueError("expected two distinct candidate hypotheses")
    if any(x.get("status")!="HYPOTHESIS_NOT_VERIFIED" for x in proposals["candidates"]):
        raise ValueError("hypothesis pre-adjudicated")
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24BAdapter, ID24BAsset} from "./D24BAdapter.sol";
interface ID24CEconomic {
    function vaultAddress() external view returns (address);
    function nonRebasingSupply() external view returns (uint256);
    function changeSupply(uint256) external;
    function rebaseOptOut() external;
    function rebaseOptIn() external;
    function transferFrom(address,address,uint256) external returns (bool);
}
contract D24CGeneratedEconomicTest is Test {
    D24BAdapter internal deployer;
    ID24BAsset internal asset;
    ID24CEconomic internal economic;
    address constant OWNER = address(0x30000);
    address constant COUNTERPARTY = address(0x40000);
    address constant SPENDER = address(0x50000);
    function setUp() public {
        deployer = new D24BAdapter();
        asset = ID24BAsset(deployer.assetAddress());
        economic = ID24CEconomic(address(asset));
        deployer.mint(0, 1000 ether);
    }
    function testFuzz_PRISMNonrebasingIsolation(uint96 entropy) public {
        // Dependency path: mint -> fund rebasing counterparty -> opt out
        // -> increase supply via the actual vault -> opt in.
        vm.prank(OWNER);
        require(asset.transfer(COUNTERPARTY, 400 ether), "D24C_FUNDING_FAILED");
        vm.prank(OWNER);
        economic.rebaseOptOut();
        uint256 excludedBalance = asset.balanceOf(OWNER);
        uint256 earningBefore = asset.balanceOf(COUNTERPARTY);
        uint256 supplyBefore = asset.totalSupply();
        uint256 nonRebasing = economic.nonRebasingSupply();
        require(supplyBefore > nonRebasing, "D24C_NO_REBASING_SUPPLY");
        uint256 gain = 1 ether + (uint256(entropy) % (100 ether));
        vm.prank(economic.vaultAddress());
        economic.changeSupply(supplyBefore + gain);
        require(asset.balanceOf(OWNER) == excludedBalance,
                "D24C_REBASE_LEAK_TO_NONREBASING");
        require(asset.totalSupply() == supplyBefore + gain,
                "D24C_SUPPLY_DELTA_MISMATCH");
        // Public-state pro-rata rebasing share. OUSD starts with other holders;
        // no holder may be assumed to be the sole yield recipient.
        uint256 expectedEarning = earningBefore
            + (gain * earningBefore) / (supplyBefore - nonRebasing);
        uint256 received = asset.balanceOf(COUNTERPARTY);
        uint256 deviation = received >= expectedEarning
            ? received - expectedEarning : expectedEarning - received;
        require(deviation <= 1e9, "D24C_REBASING_YIELD_DRIFT");
        vm.prank(OWNER);
        economic.rebaseOptIn();
        require(asset.balanceOf(OWNER) == excludedBalance,
                "D24C_TOGGLE_LOSS");
    }
    function testFuzz_PRISMSpenderDebit(uint96 entropy) public {
        // Dependency path: mint -> approve -> transferFrom -> allowance readback.
        uint256 amount = 1 ether + (uint256(entropy) % (99 ether));
        uint256 approved = amount + 100 ether;
        vm.prank(OWNER);
        require(asset.approve(SPENDER, approved), "D24C_APPROVAL_FAILED");
        vm.prank(SPENDER);
        require(economic.transferFrom(OWNER, COUNTERPARTY, amount),
                "D24C_TRANSFERFROM_FAILED");
        require(asset.allowance(OWNER, SPENDER) == approved - amount,
                "D24C_ALLOWANCE_NOT_DEBITED");
    }
}
""".replace("ID24CEconomic", "ID24CEconomic")

def compile_candidates(abi_path: Path, target: Path, output: Path)->dict:
    if any(b in str(abi_path).lower() for b in ("judge","known-bug","canary","exploit")):
        raise ValueError("label-contaminated detector input path")
    raw=abi_path.read_bytes()
    report=choose(json.loads(raw))
    if report["unknown"]:
        raise ValueError("source ABI cannot support complete economic protocol")
    outsol=target/"test"/"recon"/"D24CGeneratedEconomic.t.sol"
    if not (target/"test"/"recon"/"D24BAdapter.sol").is_file():
        raise FileNotFoundError("require pinned D2.4B observation adapter")
    outsol.write_text(solidity(report),encoding="utf-8")
    output.mkdir(parents=True,exist_ok=True)
    report.update({"status":"CANDIDATES_NOT_VERIFIED",
                  "abi_sha256":sha256(raw).hexdigest(),
                  "solidity_sha256":sha256(outsol.read_bytes()).hexdigest(),
                  "verified_vulnerabilities":None,
                  "target_mutated":False})
    (output/"proposals.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--abi",required=True,type=Path)
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    r=compile_candidates(a.abi,a.root,a.output)
    print("D24C_CANDIDATES",[x["id"] for x in r["candidates"]])
