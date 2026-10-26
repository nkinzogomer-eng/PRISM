"""Deterministic randomized *laboratory* holdout and label-free EVM replay.

The verifier receives only ABI and opaque instance IDs. The benchmark maker
keeps labels out of the planner and native probe; labels are opened in grade.
This tests a real autonomous trace search on generated Solidity, not discovery
of a new public incident, economic exploit, vulnerability family or zero-day.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import re
import sys

from prism.d24p_probe import propose_trials


ABI = [
    {"type":"function","name":"deposit","stateMutability":"payable","inputs":[]},
    {"type":"function","name":"withdraw","stateMutability":"nonpayable","inputs":[]},
    {"type":"function","name":"balances","stateMutability":"view",
     "inputs":[{"type":"address"}]},
]

_PAYOUT = '''(bool paid,) = msg.sender.call{value:amount}("");
        require(paid, "PAYMENT_FAILED");'''


def _contract(case_id: int, variant: int) -> str:
    # The source contains no "vulnerable" or "safe" name and exposes the
    # same external ABI in every variant. Labels exist only in sealed JSON.
    if variant == 0:
        withdraw = f'{_PAYOUT}\n        balances[msg.sender] = 0;'
    elif variant == 1:
        withdraw = f'{_PAYOUT}\n        balances[msg.sender] -= amount;'
    elif variant == 2:
        withdraw = f'balances[msg.sender] = 0;\n        {_PAYOUT}'
    elif variant == 3:
        withdraw = f'balances[msg.sender] -= amount;\n        {_PAYOUT}'
    elif variant == 4:
        withdraw = ('''require(!_locked, "LOCKED");
        _locked = true;
        ''' + _PAYOUT + '''
        balances[msg.sender] = 0;
        _locked = false;''')
    elif variant == 5:
        withdraw = ('''require(!_locked, "LOCKED");
        _locked = true;
        ''' + _PAYOUT + '''
        balances[msg.sender] -= amount;
        _locked = false;''')
    else:
        raise ValueError('INVALID_TEMPLATE')
    return f'''contract D24PInstance{case_id} {{
    mapping(address => uint256) public balances;
    bool private _locked;
    uint256 private _unrelatedCounter;
    function deposit() external payable {{
        require(msg.value > 0, "ZERO_DEPOSIT");
        balances[msg.sender] += msg.value;
        _unrelatedCounter += 1;
    }}
    function withdraw() external {{
        uint256 amount = balances[msg.sender];
        require(amount > 0, "EMPTY");
        {withdraw}
    }}
    function irrelevantCounter() external view returns (uint256) {{
        return _unrelatedCounter;
    }}
}}
'''


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def generate(out: Path, *, seed: int, cases: int = 18) -> dict:
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError('BAD_HOLDOUT_SEED')
    if type(cases) is not int or cases < 6 or cases > 30 or cases % 6:
        raise ValueError('INVALID_COHORT_SIZE')
    rng=random.Random(seed)
    variants=list(range(6))*(cases//6)
    rng.shuffle(variants)
    src='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n\n'
    src+='\n'.join(_contract(i,v) for i,v in enumerate(variants))
    src+='contract D24PInstanceFactory {\n'
    src+='    function deploy(uint256 id) external returns (address) {\n'
    for i in range(cases):
        src+=f'        if (id == {i}) return address(new D24PInstance{i}());\n'
    src+='        revert("UNKNOWN_INSTANCE");\n    }\n}\n'
    _write(out/'src'/'Instances.sol',src)
    _write(out/'public_abi.json',json.dumps(ABI,sort_keys=True,indent=2)+'\n')
    # The only file disclosing labels is *not* loaded by propose_trials or
    # by the emitted Foundry test. The grading stage reads it later.
    ground_truth=[{"case":i,"family":"reentrancy_eth_liability_shortfall",
                   "expected_evm_witness":v in (0,1),"template_private":v}
                  for i,v in enumerate(variants)]
    _write(out/'sealed_labels.json',json.dumps(ground_truth,indent=2)+'\n')
    _write(out/'foundry.toml','''[profile.default]
src = "src"
test = "test"
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 200
''')
    return {"seed":seed,"cases":cases,"source_sha256":sha256(src.encode()).hexdigest(),
            "labels_sha256":sha256((out/'sealed_labels.json').read_bytes()).hexdigest(),
            "source_disclosed_to_prober_only":True}


def _solidity_probe(trials: list[dict], *, cases: int) -> str:
    if not trials or len(trials) > 48:
        raise ValueError('NO_BOUNDED_PROBES')
    sections=[]
    for item in trials:
        a,h,b=item['stake_ether'],item['honest_ether'],item['callback_retry_budget']
        if not (a in (1,2) and h in (1,2,3) and b in (0,1,2)):
            raise ValueError('PROBE_OUTSIDE_FROZEN_BUDGET')
        sections.append(f'            if (_attempt(i, {h}, {a}, {b})) hit = true;')
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "../src/Instances.sol";

interface D24PAccount {
    function deposit() external payable;
    function withdraw() external;
    function balances(address who) external view returns (uint256);
}

contract D24PGenericCallback {
    D24PAccount internal target;
    uint256 internal retryBudget;
    uint256 internal retried;
    function execute(D24PAccount vault, uint256 maxRetries) external payable {
        target = vault;
        retryBudget = maxRetries;
        vault.deposit{value:msg.value}();
        vault.withdraw();
    }
    receive() external payable {
        if (retried < retryBudget) {
            ++retried;
            // Reentry is a generated action. Failure is an observation, not
            // an assertion that either side is safe or vulnerable.
            (bool ok,) = address(target).call(abi.encodeWithSelector(D24PAccount.withdraw.selector));
            if (!ok) { return; }
        }
    }
}

interface D24PCheat {
    function deal(address who, uint256 amount) external;
}

contract D24PAutonomousNativeProbe {
    event log_string(string message);
    D24PCheat constant vm = D24PCheat(address(uint160(uint256(keccak256("hevm cheat code")))));
    D24PInstanceFactory internal factory;
    function setUp() public {
        vm.deal(address(this), 100000 ether);
        factory = new D24PInstanceFactory();
    }

    function _attempt(uint256 index, uint256 honest, uint256 attacker, uint256 retries)
        internal returns (bool)
    {
        // Fresh deployment for every hypothesis, no state leakage across trials.
        D24PAccount vault = D24PAccount(factory.deploy(index));
        D24PGenericCallback actor = new D24PGenericCallback();
        vault.deposit{value: honest * 1 ether}();
        try actor.execute{value:attacker * 1 ether}(vault, retries) {
            uint256 received = address(actor).balance;
            uint256 stillOwedHonest = vault.balances(address(this));
            uint256 available = address(vault).balance;
            // Both net attacker profit and an unpaid independent honest
            // depositor's liability are REQUIRED for a financial witness.
            return received > attacker * 1 ether && available < stillOwedHonest
                && stillOwedHonest == honest * 1 ether;
        } catch { return false; }
    }

    function test_label_free_bounded_native_search() public {
        for (uint256 i = 0; i < '''+str(cases)+'''; ++i) {
            bool hit = false;
'''+ '\n'.join(sections) +'''
            if (hit) {
                // The native probe has no access to sealed labels.
                emit log_string(string(abi.encodePacked("D24P_WITNESS_", _number(i))));
            } else {
                emit log_string(string(abi.encodePacked("D24P_NO_WITNESS_", _number(i))));
            }
        }
    }

    function _number(uint256 n) internal pure returns (string memory) {
        if (n == 0) return "0";
        uint256 d = n;
        uint256 size;
        while (d != 0) { ++size; d /= 10; }
        bytes memory out = new bytes(size);
        while (n != 0) { out[--size] = bytes1(uint8(48 + (n % 10))); n /= 10; }
        return string(out);
    }
}
'''


def plan(out:Path) -> dict:
    abi=json.loads((out/'public_abi.json').read_text())
    proposal=propose_trials(abi)
    if proposal['status']!='READY_FOR_NATIVE_EVM_SEARCH_NOT_VERIFIED':
        raise ValueError('ABI_NOT_SUPPORTED')
    # Restrict the plan to what was made visible in the public ABI.
    cases=len(re.findall(r'contract D24PInstance\d+\s*\{',
                         (out/'src'/'Instances.sol').read_text()))
    _write(out/'test'/'D24PBlindProbe.t.sol',_solidity_probe(proposal['trials'],cases=cases))
    _write(out/'trial_plan.json',json.dumps(proposal,sort_keys=True,indent=2)+'\n')
    return {'cases':cases,'plans_per_case':len(proposal['trials']),
            'abi_sha256':proposal['abi_sha256'],
            'scanner_received_ground_truth':False}


def grade(out:Path) -> dict:
    text=(out/'forge-output.txt').read_text()
    if 'Suite result: ok.' not in text and 'Test result: ok.' not in text:
        raise ValueError('NATIVE_EVM_SUITE_NOT_SUCCESSFUL')
    labels=json.loads((out/'sealed_labels.json').read_text())
    found=re.findall(r'\bD24P_WITNESS_(\d+)\b',text)
    missed=re.findall(r'\bD24P_NO_WITNESS_(\d+)\b',text)
    ids=[int(v) for v in found+missed]
    if (len(ids)!=len(labels) or set(ids)!=set(range(len(labels))) or
        len(ids)!=len(set(ids))):
        raise ValueError('MISSING_DUPLICATED_OR_UNOBSERVED_CASE')
    found_ids={int(v) for v in found}
    tp=sum(x['expected_evm_witness'] and x['case'] in found_ids for x in labels)
    fn=sum(x['expected_evm_witness'] and x['case'] not in found_ids for x in labels)
    fp=sum(not x['expected_evm_witness'] and x['case'] in found_ids for x in labels)
    tn=sum(not x['expected_evm_witness'] and x['case'] not in found_ids for x in labels)
    result={'schema':'scm.prism.d24p.native-generated-holdout.v1',
            'native_evm_tests_passed':1,'independently_observed_evm_case_count':len(labels),
            'true_positive':tp,'false_negative':fn,'false_positive':fp,'true_negative':tn,
            'native_witness_count':len(found_ids),
            'generator_seed':json.loads((out/'registration.json').read_text())['seed'],
            'lab_generated_reentrancy_family_only':True,
            'independently_discovered_public_vulnerabilities':0,
            'novel_vulnerability_families':0,'zero_days':0,
            'limitation':'Random-seed held-out variants generated from human-authored fixed templates; not unseen real-world code or a zero-day.'}
    _write(out/'result.json',json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


def main() -> None:
    cli=argparse.ArgumentParser()
    cli.add_argument('stage',choices=['generate','plan','grade'])
    cli.add_argument('--out',type=Path,required=True)
    cli.add_argument('--seed',type=int)
    args=cli.parse_args()
    if args.stage=='generate':
        if args.seed is None: cli.error('--seed required for generate')
        result=generate(args.out,seed=args.seed)
        _write(args.out/'registration.json',json.dumps(result,sort_keys=True,indent=2)+'\n')
    elif args.stage=='plan':result=plan(args.out)
    else:result=grade(args.out)
    print('D24P_'+args.stage.upper(),json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
