"""D2.4R: independently replay bounded unauthorized treasury hypotheses on Safe.

Pre-registration preceded inspection of Safe source. The *separate* known
uninitialized-proxy experiment is retrospective and never a blind discovery.
No production wallets, private keys, or live chains are contacted.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from prism.d24r_zero_capital_probe import propose_treasury_trials


REPOSITORY = "safe-fndn/safe-smart-account"
REVISION = "bf943f80fec5ac647159d26161446ac5d716a294"
SOURCE = "contracts/Safe.sol"
PROXY = "contracts/proxies/SafeProxy.sol"

_INTERFACE = {
    "setup": ("address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address"),
    "execTransaction": ("address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"),
    "execTransactionFromModule": ("address", "uint256", "bytes", "uint8"),
    "addOwnerWithThreshold": ("address", "uint256"),
    "changeThreshold": ("uint256",),
    "getThreshold": (),
    "isOwner": ("address",),
}
ABI = [{"type": "function", "name": name, "inputs": [{"type": t} for t in types]}
       for name, types in _INTERFACE.items()]


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *arguments], text=True,
                            capture_output=True, check=False, timeout=30)
    if result.returncode:
        raise ValueError("FROZEN_SOURCE_ATTESTATION_FAILED: " + result.stderr[-200:])
    return result.stdout.strip()


def attest_source(repo: Path) -> dict:
    if _git(repo, "rev-parse", "HEAD") != REVISION:
        raise ValueError("WRONG_SOURCE_COMMIT")
    url = _git(repo, "remote", "get-url", "origin").rstrip("/").removesuffix(".git")
    if not (url.endswith("/" + REPOSITORY) or
            url.endswith("/safe-global/safe-smart-account")):
        raise ValueError("WRONG_SOURCE_ORIGIN")
    hashes = {}
    for filename in (SOURCE, PROXY):
        contents = (repo / filename).read_bytes()
        if len(contents) > 200_000:
            raise ValueError("SOURCE_EXCEEDS_SIZE_BUDGET")
        blob = _git(repo, "rev-parse", REVISION + ":" + filename)
        if blob != _git(repo, "hash-object", filename):
            raise ValueError("ORIGINAL_SOURCE_MODIFIED")
        hashes[filename] = {"git_blob_sha1": blob, "sha256": sha256(contents).hexdigest()}
    return {"repository": REPOSITORY, "revision": REVISION,
            "sources": hashes, "original_source_attested": True}


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _solidity(candidates: list[dict]) -> str:
    cases = []
    for index, candidate in enumerate(candidates):
        mode = ("unapproved_module_execution", "unsigned_direct_treasury_execution",
                "unauthorized_owner_or_threshold_change", "reinitialization_after_legitimate_setup").index(candidate["family"])
        amount = candidate["requested_transfer_units"]
        if amount not in (1, 1000, 1000000):
            raise ValueError("UNREGISTERED_AMOUNT")
        cases.append(f'''        uint8 result{index} = _tryCandidate({mode}, {amount});
        if ((result{index} & 1) != 0) emit log_string("D24R_UNAUTHORIZED_WITNESS_{index}");
        if ((result{index} & 2) != 0) emit log_string("D24R_AUTHORITY_WITNESS_{index}");''')
    return '''// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;
import "safe/contracts/Safe.sol";
import "safe/contracts/proxies/SafeProxy.sol";

interface D24RPrank { function prank(address actor) external; }

contract D24RToken {
    mapping(address => uint256) public balanceOf;
    function mintOnlyForPrivateLab(address who, uint256 amount) external {
        balanceOf[who] += amount;
    }
    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "INSUFFICIENT_LOCAL_BALANCE");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

// Deliberately flawed, locally authored *control*; not a third-party finding.
contract D24RInsecureAccount {
    function execTransactionFromModule(address to, uint256, bytes calldata data, uint8)
        external returns (bool)
    {
        (bool success,) = to.call(data);
        return success;
    }
}

contract D24RNative {
    event log_string(string);
    D24RPrank constant vm = D24RPrank(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant ATTACKER = address(0xBADD1E);
    address constant OWNER_A = address(0xA11CE);
    address constant OWNER_B = address(0xB0B);
    uint256 constant TREASURY_UNITS = 1000000;

    function _owners(bool legitimate) internal pure returns (address[] memory owners) {
        owners = new address[](legitimate ? 2 : 1);
        owners[0] = legitimate ? OWNER_A : ATTACKER;
        if (legitimate) owners[1] = OWNER_B;
    }

    function _newSafe(bool initialize) internal returns (Safe wallet, D24RToken token) {
        Safe singleton = new Safe();
        SafeProxy proxy = new SafeProxy(address(singleton));
        wallet = Safe(payable(address(proxy)));
        token = new D24RToken();
        if (initialize) {
            wallet.setup(_owners(true), 2, address(0), new bytes(0),
                         address(0), address(0), 0, payable(address(0)));
        }
        token.mintOnlyForPrivateLab(address(wallet), TREASURY_UNITS);
    }

    function _transferCalldata(address recipient, uint256 amount)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
    }

    function _tryCandidate(uint8 mode, uint256 amount) internal returns (uint8 result) {
        (Safe wallet, D24RToken token) = _newSafe(true);
        bytes memory payment = _transferCalldata(ATTACKER, amount);
        bytes memory callData;
        if (mode == 0) {
            // Direct execution as an unregistered module.
            callData = abi.encodeWithSignature(
                "execTransactionFromModule(address,uint256,bytes,uint8)",
                address(token), 0, payment, uint8(0));
        } else if (mode == 1) {
            // Direct unsigned transaction, with no owner signature.
            callData = abi.encodeWithSignature(
                "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
                address(token), 0, payment, uint8(0), 0, 0, 0,
                address(0), address(0), new bytes(0));
        } else if (mode == 2) {
            // Both owner mutations require the wallet's own authorization.
            if (amount == 1)
                callData = abi.encodeWithSignature("changeThreshold(uint256)", 1);
            else
                callData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", ATTACKER, 1);
        } else {
            // Attempt to set attacker-controlled owner and receive a setup refund.
            callData = abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                _owners(false), 1, address(0), new bytes(0), address(0),
                address(token), amount, ATTACKER);
        }
        vm.prank(ATTACKER);
        (bool accepted,) = address(wallet).call(callData);
        bool unauthorizedTransfer = token.balanceOf(ATTACKER) > 0;
        bool authorityChanged = wallet.isOwner(ATTACKER) || wallet.getThreshold() != 2;
        if (unauthorizedTransfer) result |= 1;
        if (authorityChanged) result |= 2;
        require(!accepted || !unauthorizedTransfer || authorityChanged ||
                token.balanceOf(address(wallet)) < TREASURY_UNITS,
                "INCONSISTENT_EVM_OBSERVATION");
        // All results, including reverts and no-witness cases, are observations;
        // a rejected candidate never proves general wallet safety.
    }

    function test_frozen_bounded_safe_hypotheses() public {
'''+"\n".join(cases)+'''
        emit log_string("D24R_FROZEN_TRIALS_EXECUTED");
    }

    function test_positive_auth_bypass_control_detected() public {
        D24RToken token = new D24RToken();
        D24RInsecureAccount unsafe = new D24RInsecureAccount();
        token.mintOnlyForPrivateLab(address(unsafe), TREASURY_UNITS);
        vm.prank(ATTACKER);
        bool executed = unsafe.execTransactionFromModule(
            address(token), 0, _transferCalldata(ATTACKER, TREASURY_UNITS), 0);
        require(executed && token.balanceOf(ATTACKER) == TREASURY_UNITS,
                "POSITIVE_CONTROL_NOT_DETECTED");
        emit log_string("D24R_AUTHORED_POSITIVE_CONTROL_WITNESS");
    }

    function test_exploratory_preinitialization_risk_is_known_not_novel() public {
        // Intentionally outside the preregistered legitimate-setup threat model.
        // Safe's original source explicitly documents this unsafe deployment.
        (Safe wallet, D24RToken token) = _newSafe(false);
        vm.prank(ATTACKER);
        wallet.setup(_owners(false), 1, address(0), new bytes(0),
                     address(0), address(token), TREASURY_UNITS, payable(ATTACKER));
        require(token.balanceOf(ATTACKER) == TREASURY_UNITS &&
                token.balanceOf(address(wallet)) == 0,
                "EXPLORATORY_KNOWN_BAD_DEPLOYMENT_NOT_REPRODUCED");
        emit log_string("D24R_KNOWN_UNINITIALIZED_PROXY_CONFIGURATION_WITNESS");
    }
}
'''


def prepare(repo: Path, output: Path) -> dict:
    source = attest_source(repo)
    plan = propose_treasury_trials(ABI)
    if plan["status"] != "FROZEN_HYPOTHESES_AWAIT_NATIVE_EVM":
        raise ValueError("UNSUPPORTED_NATIVE_INTERFACE")
    _write(output / "foundry.toml", '''[profile.default]
src = "src"
test = "test"
solc_version = "0.7.6"
optimizer = true
optimizer_runs = 200
remappings = ["safe/=lib/safe/"]
''')
    _write(output / "test" / "D24RSafeNative.t.sol", _solidity(plan["candidates"]))
    _write(output / "trial_plan.json", json.dumps(plan, indent=2, sort_keys=True) + "\n")
    _write(output / "source_attestation.json", json.dumps(source, indent=2, sort_keys=True) + "\n")
    return {"status": "NATIVE_PENDING_NO_ZERO_DAY_CLAIM",
            "frozen_candidates": len(plan["candidates"]), "source": source}


def score(output: Path) -> dict:
    trace = (output / "forge-output.txt").read_text(encoding="utf-8")
    required = ("D24R_FROZEN_TRIALS_EXECUTED", "D24R_AUTHORED_POSITIVE_CONTROL_WITNESS",
                "D24R_KNOWN_UNINITIALIZED_PROXY_CONFIGURATION_WITNESS")
    if "Suite result: ok." not in trace or any(trace.count(marker) != 1 for marker in required):
        raise ValueError("INCOMPLETE_OR_FAILED_NATIVE_TEST_EVIDENCE")
    witness_indices = [int(i) for i in re.findall(r"\bD24R_UNAUTHORIZED_WITNESS_(\d+)\b", trace)]
    authority_indices = [int(i) for i in re.findall(r"\bD24R_AUTHORITY_WITNESS_(\d+)\b", trace)]
    n = len(json.loads((output / "trial_plan.json").read_text())["candidates"])
    if (len(set(witness_indices)) != len(witness_indices) or
        len(set(authority_indices)) != len(authority_indices) or
        any(not 0 <= i < n for i in witness_indices + authority_indices)):
        raise ValueError("MALFORMED_WITNESS_LOGS")
    if authority_indices:
        status = "POTENTIAL_UNEXPECTED_AUTHORIZATION_WITNESS_REQUIRES_REPLAY"
    elif witness_indices:
        status = "POTENTIAL_NATIVE_WITNESS_REQUIRES_INDEPENDENT_REPLAY"
    else:
        status = "NO_UNAUTHORIZED_TREASURY_WITNESS_IN_FROZEN_BOUNDED_TRIALS"
    result = {
        "schema": "scm.prism.d24r.safe-native-evidence.v1",
        "status": status,
        "native_evm_executed": True,
        "real_third_party_unmodified_code_attested": True,
        "frozen_candidate_count": n,
        "frozen_treasury_witness_count": len(witness_indices),
        "frozen_authorization_witness_count": len(authority_indices),
        "frozen_treasury_witness_indices": witness_indices,
        "frozen_authorization_witness_indices": authority_indices,
        "insecure_authored_control_detected": True,
        "uninitialized_proxy_original_source_known_deployment_risk_reproduced": True,
        "uninitialized_proxy_is_preregistered_blind_discovery": False,
        "attacker_starting_assets": 0,
        "gas_fee_or_sponsorship_verified": False,
        "actual_zero_expense_proved": False,
        "confirmed_novel_public_vulnerabilities": 0,
        "confirmed_zero_days": 0,
        "uncovered_families": ["signature_replay_without_fresh_authorization"],
        "source_attestation": json.loads((output / "source_attestation.json").read_text())}
    _write(output / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "score"))
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.stage == "prepare":
        if args.repo is None:
            parser.error("--repo required for prepare")
        result = prepare(args.repo, args.out)
    else:
        result = score(args.out)
    print("D24R_" + args.stage.upper(), json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
