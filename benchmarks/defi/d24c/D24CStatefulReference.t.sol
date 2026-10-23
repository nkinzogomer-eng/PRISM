// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24BAdapter, ID24BAsset} from "./D24BAdapter.sol";

interface IStatefulOUSD {
    function vaultAddress() external view returns (address);
    function changeSupply(uint256) external;
    function rebaseOptOut() external;
    function nonRebasingSupply() external view returns (uint256);
    function transferFrom(address,address,uint256) external returns (bool);
}

// Independently specified external EVM stateful reference (not PRISM's
// generated test or property selection). All checks happen after actual
// state mutations; no arbitrary revert counts as a discovered bug.
contract D24CAccountingHandler is Test {
    ID24BAsset internal asset;
    IStatefulOUSD internal accounting;
    address constant HOLDER = address(0x30000);
    address constant EARNER = address(0x40000);
    address constant SPENDER = address(0x50000);
    uint256 public acceptedRebases;
    uint256 public acceptedSpendings;

    constructor(ID24BAsset a) {
        asset = a;
        accounting = IStatefulOUSD(address(a));
    }

    function rebase(uint96 entropy) external {
        uint256 oldTotal = asset.totalSupply();
        uint256 excluded = accounting.nonRebasingSupply();
        require(oldTotal > excluded, "D24C_STATEFUL_PRECONDITION");
        uint256 ownerBefore = asset.balanceOf(HOLDER);
        uint256 earnerBefore = asset.balanceOf(EARNER);
        uint256 growth = 1 ether + uint256(entropy) % (10 ether);

        vm.prank(accounting.vaultAddress());
        accounting.changeSupply(oldTotal + growth);
        require(asset.balanceOf(HOLDER) == ownerBefore, "D24C_STATEFUL_OWNER_DRIFT");
        uint256 expected = earnerBefore
            + (growth * earnerBefore) / (oldTotal - excluded);
        uint256 nowBalance = asset.balanceOf(EARNER);
        uint256 difference = nowBalance > expected
            ? nowBalance - expected : expected - nowBalance;
        require(difference <= 1e9, "D24C_STATEFUL_REBASE_YIELD");
        require(asset.totalSupply() == oldTotal + growth, "D24C_STATEFUL_SUPPLY");
        ++acceptedRebases;
    }

    function spend(uint96 entropy) external {
        uint256 ownerBalance = asset.balanceOf(HOLDER);
        if (ownerBalance <= 1 ether) return;
        uint256 upper = ownerBalance < 30 ether ? ownerBalance - 1 : 29 ether;
        uint256 amount = 1 ether + (uint256(entropy) % upper);
        uint256 allowanceLimit = amount + 10 ether;
        vm.prank(HOLDER);
        require(asset.approve(SPENDER,allowanceLimit), "D24C_STATEFUL_APPROVE");
        vm.prank(SPENDER);
        require(accounting.transferFrom(HOLDER,EARNER,amount),
                "D24C_STATEFUL_TRANSFER_FROM");
        require(asset.allowance(HOLDER,SPENDER) == allowanceLimit - amount,
                "D24C_STATEFUL_ALLOWANCE");
        ++acceptedSpendings;
    }

    function replenish(uint96 entropy) external {
        uint256 balance = asset.balanceOf(EARNER);
        if (balance <= 5 ether) return;
        uint256 amount = 1 ether + (uint256(entropy) % (4 ether));
        vm.prank(EARNER);
        require(asset.transfer(HOLDER, amount), "D24C_STATEFUL_REPLENISH");
    }
}

contract D24CStatefulReferenceTest is Test {
    D24BAdapter internal deployer;
    ID24BAsset internal token;
    D24CAccountingHandler internal handler;

    function setUp() public {
        deployer = new D24BAdapter();
        token = ID24BAsset(deployer.assetAddress());
        deployer.mint(0, 1000 ether);
        vm.prank(address(0x30000));
        require(token.transfer(address(0x40000), 400 ether), "D24C_STATEFUL_FUND");
        vm.prank(address(0x30000));
        IStatefulOUSD(address(token)).rebaseOptOut();
        handler = new D24CAccountingHandler(token);
        targetContract(address(handler));
    }

    // Handler calls themselves check accounting after each state transition.
    function invariant_positiveSupply() public view {
        require(token.totalSupply() > 0, "D24C_STATEFUL_ZERO_SUPPLY");
    }

    // Mandatory positive instrumentation control: no empty/reverted campaign
    // may pass this explicit independent, state-changing test.
    function testFuzz_CoverageSequence(uint96 a,uint96 b) public {
        handler.rebase(a);
        handler.spend(b);
        require(handler.acceptedRebases() > 0, "D24C_STATEFUL_VACUOUS_REBASE");
        require(handler.acceptedSpendings() > 0, "D24C_STATEFUL_VACUOUS_SPEND");
    }
}
