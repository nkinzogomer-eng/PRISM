"""D2.4C: ABI-triggered, manually specified multi-transaction accounting properties.

This is NOT a semantic vulnerability miner. The source-independent ERC20
templates are frozen before looking at outcomes, issue names, or fuzzer traces.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from prism.defi_property_compiler import signatures

SPECS = {
    "ALLOWANCE_SPEND_CONSERVATION": (
        "approve(address,uint256)",
        "allowance(address,address)",
        "transferFrom(address,address,uint256)",
        "balanceOf(address)",
        "totalSupply()",
    ),
    "TRANSFER_ROUNDTRIP_SUPPLY": (
        "transfer(address,uint256)",
        "balanceOf(address)",
        "totalSupply()",
    ),
}


def select(abi: object) -> dict:
    available = signatures(abi)
    chosen = []
    unknown = []
    for name, requirements in sorted(SPECS.items()):
        missing = sorted(set(requirements) - available)
        if missing:
            unknown.append({"id": name, "decision": "UNKNOWN", "missing": missing})
        else:
            chosen.append({"id": name, "decision": "CANDIDATE_UNVERIFIED",
                           "dependencies": list(requirements)})
    return {"schema": "prism-d24c-abi-multistep-v1", "candidates": chosen,
            "unknown": unknown,
            "origin": "Fixed generic ERC20 specifications, manually authored",
            "blind_holdout": False, "verified_vulnerabilities": None}


def adapter_solidity() -> str:
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {CryticTester} from "./CryticTester.sol";
contract D24CAdapter is CryticTester {
    function assetAddress() external view returns (address) { return address(ousd); }
}
interface ID24CAsset {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address,address) external view returns (uint256);
    function approve(address,uint256) external returns (bool);
    function transfer(address,uint256) external returns (bool);
    function transferFrom(address,address,uint256) external returns (bool);
}
"""


def generated_solidity(selected: dict) -> str:
    if selected.get("schema") != "prism-d24c-abi-multistep-v1":
        raise ValueError("wrong generator schema")
    ids = [c["id"] for c in selected["candidates"]]
    if len(set(ids)) != len(ids) or not set(ids) <= set(SPECS):
        raise ValueError("duplicate/foreign candidates")
    if any(c.get("decision") != "CANDIDATE_UNVERIFIED" for c in selected["candidates"]):
        raise ValueError("candidate previously adjudicated")
    methods = []
    if "ALLOWANCE_SPEND_CONSERVATION" in ids:
        methods.append("""
    // Fixed, non-vacuous approve -> spend -> spend economic sequence.
    function testFuzz_SCMMultistepAllowance(uint96 a, uint96 b) public {
        uint256 first = uint256(a) % (10 ether) + 1;
        uint256 second = uint256(b) % (10 ether) + 1;
        uint256 granted = first + second + 1 ether;
        uint256 supply = token.totalSupply();
        vm.prank(OWNER);
        require(token.approve(SPENDER, granted), "D24C_APPROVE_REVERT");
        require(token.allowance(OWNER, SPENDER) == granted, "D24C_INITIAL_APPROVAL");
        vm.prank(SPENDER);
        require(token.transferFrom(OWNER, RECEIVER, first), "D24C_FIRST_SPEND_REVERT");
        require(token.allowance(OWNER, SPENDER) == granted-first, "D24C_FIRST_DEBIT");
        vm.prank(SPENDER);
        require(token.transferFrom(OWNER, RECEIVER, second), "D24C_SECOND_SPEND_REVERT");
        require(token.allowance(OWNER, SPENDER) == 1 ether, "D24C_SECOND_DEBIT");
        require(token.totalSupply() == supply, "D24C_SPEND_SUPPLY");
    }
""")
    if "TRANSFER_ROUNDTRIP_SUPPLY" in ids:
        methods.append("""
    function testFuzz_SCMRoundTrip(uint96 a) public {
        uint256 amount = uint256(a) % (10 ether) + 1;
        uint256 supply = token.totalSupply();
        vm.prank(OWNER);
        require(token.transfer(RECEIVER, amount), "D24C_FIRST_TRANSFER_REVERT");
        require(token.totalSupply() == supply, "D24C_FIRST_TRANSFER_SUPPLY");
        uint256 returned = token.balanceOf(RECEIVER);
        require(returned > 0, "D24C_NO_RECEIVED_TOKENS");
        vm.prank(RECEIVER);
        require(token.transfer(OWNER, returned), "D24C_RETURN_TRANSFER_REVERT");
        require(token.totalSupply() == supply, "D24C_RETURN_SUPPLY");
    }
""")
    return """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24CAdapter, ID24CAsset} from "./D24CAdapter.sol";
contract D24CGeneratedAccountingTest is Test {
    address constant OWNER = address(0x30000);
    address constant RECEIVER = address(0x40000);
    address constant SPENDER = address(0x50000);
    D24CAdapter internal tester;
    ID24CAsset internal token;
    function setUp() public {
        tester = new D24CAdapter();
        token = ID24CAsset(tester.assetAddress());
        tester.mint(0, 1000 ether);
        require(token.balanceOf(OWNER) >= 100 ether, "D24C_BAD_SETUP");
    }
""" + "\n".join(methods) + "\n}\n"


def build(abi_path: Path, root: Path, out: Path) -> dict:
    if any(x in str(abi_path).lower() for x in ("known-bug", "judge", "canary", "exploit")):
        raise ValueError("judge contamination in input path")
    raw = abi_path.read_bytes()
    chosen = select(json.loads(raw))
    testdir = root / "test" / "recon"
    if not (testdir / "CryticTester.sol").is_file():
        raise FileNotFoundError("independent pinned CryticTester not found")
    adapter = testdir / "D24CAdapter.sol"
    generated = testdir / "D24CGeneratedAccounting.t.sol"
    adapter.write_text(adapter_solidity())
    generated.write_text(generated_solidity(chosen))
    out.mkdir(parents=True, exist_ok=True)
    report = {**chosen, "abi_sha256": sha256(raw).hexdigest(),
              "adapter_sha256": sha256(adapter.read_bytes()).hexdigest(),
              "generated_sha256": sha256(generated.read_bytes()).hexdigest(),
              "status": "UNVERIFIED_CANDIDATES"}
    (out / "proposals.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--abi", type=Path, required=True)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(build(a.abi, a.root, a.out), indent=2))
