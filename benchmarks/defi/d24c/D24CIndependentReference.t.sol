// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24BAdapter, ID24BAsset} from "./D24BAdapter.sol";

interface IIndependentTokenEconomics {
    function vaultAddress() external view returns (address);
    function nonRebasingSupply() external view returns (uint256);
    function changeSupply(uint256 supply) external;
    function rebaseOptOut() external;
    function rebaseOptIn() external;
    function transferFrom(address from,address to,uint256 amount) external returns(bool);
}

// Authored independently from PRISM-generated functions; same source, setup,
// predicate and fuzz input domain. This compares execution correctness only;
// it does NOT measure a planner's vulnerability discovery superiority.
contract D24CIndependentReferenceTest is Test {
    D24BAdapter private harness;
    ID24BAsset private token;
    IIndependentTokenEconomics private rebasing;
    address constant HOLDER = address(0x30000);
    address constant OTHER = address(0x40000);
    address constant OPERATOR = address(0x50000);

    function setUp() public {
        harness = new D24BAdapter();
        token = ID24BAsset(harness.assetAddress());
        rebasing = IIndependentTokenEconomics(address(token));
        harness.mint(0, 1000 ether);
    }
    function testFuzz_ReferenceRebaseIsolation(uint96 entropy) public {
        vm.startPrank(HOLDER);
        bool funded = token.transfer(OTHER, 400 ether);
        require(funded, "D24C_REF_FUNDING_FAILED");
        rebasing.rebaseOptOut();
        vm.stopPrank();

        uint256 holderBefore = token.balanceOf(HOLDER);
        uint256 otherBefore = token.balanceOf(OTHER);
        uint256 supplyBefore = token.totalSupply();
        uint256 excluded = rebasing.nonRebasingSupply();
        require(supplyBefore > excluded, "D24C_REF_NO_REBASING_SUPPLY");
        uint256 yieldAmount = 1 ether + (uint256(entropy) % (100 ether));

        vm.prank(rebasing.vaultAddress());
        rebasing.changeSupply(supplyBefore + yieldAmount);
        require(token.balanceOf(HOLDER) == holderBefore, "D24C_REF_NONREBASE_DRIFT");
        require(token.totalSupply() == supplyBefore + yieldAmount, "D24C_REF_SUPPLY_DRIFT");
        uint256 intended = otherBefore
            + (yieldAmount * otherBefore) / (supplyBefore - excluded);
        uint256 actual = token.balanceOf(OTHER);
        uint256 gap = intended > actual ? intended - actual : actual - intended;
        require(gap <= 1e9, "D24C_REF_YIELD_ACCOUNTING_DRIFT");

        vm.prank(HOLDER);
        rebasing.rebaseOptIn();
        require(token.balanceOf(HOLDER) == holderBefore, "D24C_REF_OPTIN_DRIFT");
    }

    function testFuzz_ReferenceSpenderDebit(uint96 entropy) public {
        uint256 amount = 1 ether + (uint256(entropy) % (99 ether));
        uint256 approved = 100 ether + amount;
        vm.prank(HOLDER);
        require(token.approve(OPERATOR, approved), "D24C_REF_APPROVAL_FAILED");
        vm.prank(OPERATOR);
        bool moved = rebasing.transferFrom(HOLDER, OTHER, amount);
        require(moved, "D24C_REF_SPENDER_TRANSFER_FAILED");
        require(token.allowance(HOLDER, OPERATOR) == approved - amount,
                "D24C_REF_ALLOWANCE_DRIFT");
    }
}
