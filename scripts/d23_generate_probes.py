"""D2.3: generate concrete Solidity security checks from ABI-selected hypotheses.

No vulnerability labels or model-found traces are read. Instead the runner
deploys each provided opaque, local configuration and executes the SAME
predeclared financial witness template against it. Template selection comes
from ABI capabilities, not from a fixture's vulnerability marker.

This is an automated unit/property probe generator, not a general fuzz engine
and not proof that source ABI alone determines Solidity semantics.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


PROPERTY_ORDER = ("ORACLE_AUTH","REPAY_CONSERVATION","WITHDRAW_SOLVENCY")
EXPECTED_VARIATIONS = 4


def _validate_variations(raw: object) -> list[dict]:
    if not isinstance(raw,dict) or raw.get("schema")!="prism-d23-local-deployments-v1":
        raise ValueError("incorrect deployment manifest")
    entries=raw.get("variations")
    if not isinstance(entries,list) or len(entries)!=EXPECTED_VARIATIONS:
        raise ValueError("D2.3 requires four local configurations")
    valid_keys={"id","oracle_owner_only","withdraw_debt_check","repay_transfers_asset"}
    ids=set()
    for x in entries:
        if not isinstance(x,dict) or set(x)!=valid_keys:
            raise ValueError("unexpected or missing fixture metadata")
        ident=x["id"]
        if not isinstance(ident,str) or len(ident)<2 or not ident.isalnum() or ident in ids:
            raise ValueError("invalid or duplicated deployment id")
        ids.add(ident)
        if any(not isinstance(x[k],bool) for k in valid_keys-{"id"}):
            raise ValueError("deployment feature flags must be booleans")
    return entries


def _bool(v: bool) -> str:
    return "true" if v else "false"


def _method(prop: str, cfg: dict) -> str:
    ident=cfg["id"]
    prefix=f"""
    function testD23_{ident}_{prop}() external {{
        (D22Coin collateral,D22Coin loan,D22Oracle oracle,
          D22Credit market,D22Actor actor) = fixture(
              {_bool(cfg['oracle_owner_only'])},
              {_bool(cfg['withdraw_debt_check'])},
              {_bool(cfg['repay_transfers_asset'])});
"""
    if prop=="ORACLE_AUTH":
        content="""
        // Non-owner actor attempts to update an oracle controlled by test deployer.
        bool succeeded=false;
        try actor.changePrice(oracle,20) { succeeded=true; } catch {}
        require(!succeeded || oracle.price()==2, "D23_ORACLE_AUTH_WITNESS");
"""
    elif prop=="WITHDRAW_SOLVENCY":
        content="""
        actor.deposit(collateral,market,10);
        actor.borrow(market,10);
        // A partial withdrawal should not leave more debt than the contract limit.
        try actor.withdraw(market,10) {} catch {}
        require(market.debt(address(actor)) <= market.limit(address(actor)),
                "D23_WITHDRAW_SOLVENCY_WITNESS");
"""
    elif prop=="REPAY_CONSERVATION":
        content="""
        actor.deposit(collateral,market,10);
        actor.borrow(market,10);
        uint256 poolBefore=loan.balanceOf(address(market));
        uint256 actorBefore=loan.balanceOf(address(actor));
        uint256 debtBefore=market.debt(address(actor));
        actor.repay(loan,market,10);
        require(debtBefore==market.debt(address(actor))+10,
                "D23_REPAY_DEBT_MISMATCH");
        require(loan.balanceOf(address(market))==poolBefore+10
                && loan.balanceOf(address(actor))+10==actorBefore,
                "D23_REPAY_CONSERVATION_WITNESS");
"""
    else:
        raise ValueError("unknown compiler-generated property")
    return prefix + content + "    }\n"


def generate(compiled: dict, manifest: dict) -> str:
    if compiled.get("schema")!="prism-d23-property-compiler-v1":
        raise ValueError("unknown compiler provenance")
    ids=[x.get("identifier") for x in compiled.get("hypotheses",[])
         if x.get("decision")=="CANDIDATE_REQUIRES_DYNAMIC_VERIFICATION"]
    if len(ids)!=len(set(ids)) or any(x not in PROPERTY_ORDER for x in ids):
        raise ValueError("duplicate/unknown property hypothesis")
    entries=_validate_variations(manifest)
    methods=[]
    for cfg in entries:
        for prop in sorted(ids):
            methods.append(_method(prop,cfg))
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// Auto-generated from ABI property templates and OPAQUE local configurations.
// The generator has NOT consulted vulnerability labels, source model exploits
// or native Foundry fuzz outcomes. Failed test = observed property violation.
import {D22Coin,D22Oracle,D22Credit,D22Actor} from "../src/MultiRisk.sol";

contract D23AutoPropertyTest {
    function fixture(bool ownerOnly,bool safeWithdraw,bool fundedRepay)
        internal returns (D22Coin collateral,D22Coin loan,D22Oracle oracle,
                          D22Credit market,D22Actor actor)
    {
        collateral=new D22Coin();
        loan=new D22Coin();
        oracle=new D22Oracle(ownerOnly);
        market=new D22Credit(collateral,loan,oracle,safeWithdraw,fundedRepay);
        actor=new D22Actor();
        collateral.mint(address(actor),100);
        loan.mint(address(actor),100);
        loan.mint(address(market),1000);
    }
''' + "\n".join(methods) + "\n}\n"


def build(properties_file: Path, manifest_file: Path, root: Path, out: Path) -> dict:
    compiled=json.loads(properties_file.read_text(encoding="utf-8"))
    manifest=json.loads(manifest_file.read_text(encoding="utf-8"))
    source=generate(compiled,manifest)
    path=root/"test"/"D23AutoProperty.t.sol"
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(source,encoding="utf-8")
    ledger={
        "phase":"D2.3",
        "status":"GENERATED_NOT_EVM_VERIFIED",
        "input_property_sha256":sha256(properties_file.read_bytes()).hexdigest(),
        "input_config_sha256":sha256(manifest_file.read_bytes()).hexdigest(),
        "generated_test_sha256":sha256(path.read_bytes()).hexdigest(),
        "selected_properties":sorted(x["identifier"] for x in compiled["hypotheses"]),
        "variant_ids":[x["id"] for x in _validate_variations(manifest)],
        "test_count":source.count("function testD23_"),
        "limitations":[
            "Candidate templates are conventional and hand-authored",
            "Opaque local configurations disclose controls in their boolean values",
            "The test input/operation templates are deliberately specific to this local lab",
            "No hidden real-world holdout, no automatic Solidity semantic analysis",
            "Native stateful fuzzing remains an independently competent baseline",
        ],
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"d23-probe-generation.json").write_text(
        json.dumps(ledger,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("D23_PROBES",ledger["test_count"],"ON_CONFIGS",ledger["variant_ids"])
    return ledger


if __name__=="__main__":
    cli=argparse.ArgumentParser()
    cli.add_argument("--properties",type=Path,required=True)
    cli.add_argument("--manifest",type=Path,required=True)
    cli.add_argument("--root",type=Path,required=True)
    cli.add_argument("--output",type=Path,required=True)
    args=cli.parse_args()
    build(args.properties.resolve(),args.manifest.resolve(),args.root.resolve(),args.output.resolve())
