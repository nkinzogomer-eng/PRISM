"""Label-free ERC4626 native-EVM economic trial enumeration.

This is an intentionally narrow *new* economic-property grammar. It proposes
sequences, not security verdicts, before seeing the external vault source.
Only a Solidity EVM observer can confirm value transfer or rejection.
"""
from __future__ import annotations

from hashlib import sha256
from itertools import product
import json


_REQUIRED = {
    ('deposit', ('uint256','address')),
    ('redeem', ('uint256','address','address')),
    ('balanceOf', ('address',)),
    ('totalAssets', ()),
    ('totalSupply', ()),
}


def propose_asset_share_trials(abi:list[dict],*,max_trials:int=27)->dict:
    if type(abi) is not list or len(abi)>256 or len(json.dumps(abi))>100_000:
        raise ValueError('INVALID_ABI_BUDGET')
    if type(max_trials) is not int or not 1<=max_trials<=27:
        raise ValueError('INVALID_TEST_BUDGET')
    observed=set()
    for method in abi:
        if not isinstance(method,dict) or method.get('type')!='function':continue
        inputs=method.get('inputs',[])
        if not isinstance(inputs,list):raise ValueError('INVALID_INPUTS')
        observed.add((method.get('name'),tuple(x.get('type') for x in inputs)))
    missing=sorted(_REQUIRED-observed)
    if missing:
        return {'schema':'scm.prism.d24q.asset-share-trials.v1',
                'status':'UNSUPPORTED_ABI_UNKNOWN_NOT_SAFE','missing':repr(missing),
                'candidates':[],'verified_flaws':0,'zero_days':0}
    # All amounts are in *raw wei-like underlying token units* and only
    # represent an adapter hypothesis until the external token's decimals,
    # restrictions and hooks are independently verified.
    candidates=[]
    for seed, donation, victim in product((1,2,5),(10,100,1000),(10,100,1000)):
        candidates.append({'seed_units':seed,'donation_units':donation,
                           'victim_deposit_units':victim,
                           'actions':['attacker_deposit','unmatched_asset_transfer',
                                      'victim_deposit','attacker_redeem','observe_value'],
                           'required_observations':['net_attacker_value_after_costs',
                                    'victim_share_delta','original_no_donation_control',
                                    'actual_total_assets_and_supply']})
    return {'schema':'scm.prism.d24q.asset-share-trials.v1',
            'abi_sha256':sha256(json.dumps(abi,sort_keys=True).encode()).hexdigest(),
            'status':'UNVERIFIED_EVM_SEARCH_PENDING','candidates':candidates[:max_trials],
            'omitted_for_budget':27-min(len(candidates),max_trials),
            'verified_flaws':0,'zero_days':0,
            'limits':['Only ERC4626-like tokenized vault ABI, no semantic completeness',
                      'Potential redistribution is distinct from a protocol security verdict',
                      'Zero candidates, reverting trials and failed adapter mean UNKNOWN',
                      'No offchain API, actual financial attack or live chain is used']}
