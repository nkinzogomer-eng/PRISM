// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24CAdapter, ID24CAsset} from "./D24CAdapter.sol";

// Independently implemented direct Foundry reference, identical operation
// budgets and input ranges to generated checks; separate from the stateful run.
contract D24CIndependentReferenceTest is Test {
    ID24CAsset internal t;
    address constant ALICE = address(0x30000);
    address constant BOB = address(0x40000);
    address constant DELEGATE = address(0x50000);
    function setUp() public {
        D24CAdapter environment = new D24CAdapter();
        t = ID24CAsset(environment.assetAddress());
        environment.mint(0, 1000 ether);
        assertGe(t.balanceOf(ALICE), 100 ether);
    }

    function testFuzz_ReferenceAllowance(uint96 p, uint96 q) public {
        uint256 n = uint256(p) % (10 ether) + 1;
        uint256 m = uint256(q) % (10 ether) + 1;
        uint256 budget = n + m + 1 ether;
        uint256 total = t.totalSupply();
        vm.prank(ALICE);
        assertTrue(t.approve(DELEGATE, budget));
        assertEq(t.allowance(ALICE, DELEGATE), budget, "D24C_REF_APPROVAL");
        vm.prank(DELEGATE);
        assertTrue(t.transferFrom(ALICE, BOB, n));
        assertEq(t.allowance(ALICE, DELEGATE), budget - n, "D24C_REF_FIRST");
        vm.prank(DELEGATE);
        assertTrue(t.transferFrom(ALICE, BOB, m));
        assertEq(t.allowance(ALICE, DELEGATE), 1 ether, "D24C_REF_SECOND");
        assertEq(t.totalSupply(), total, "D24C_REF_SUPPLY");
    }

    function testFuzz_ReferenceRoundTrip(uint96 p) public {
        uint256 quantity = uint256(p) % (10 ether) + 1;
        uint256 total = t.totalSupply();
        vm.prank(ALICE);
        assertTrue(t.transfer(BOB, quantity));
        assertEq(t.totalSupply(), total, "D24C_REF_TRANSFER");
        uint256 available = t.balanceOf(BOB);
        assertGt(available, 0);
        vm.prank(BOB);
        assertTrue(t.transfer(ALICE, available));
        assertEq(t.totalSupply(), total, "D24C_REF_RETURN");
    }
}

// Independent multi-transaction stateful baseline. All operations immediately
// check the relevant predicate; an unsuccessful action is never counted a pass.
contract D24CStatefulHandler is Test {
    ID24CAsset public token;
    uint256 public checks;
    uint256 public spends;
    uint256 public returns;
    address constant A = address(0x30000);
    address constant B = address(0x40000);
    address constant S = address(0x50000);
    constructor(ID24CAsset source) { token = source; }

    function allowanceSequence(uint96 x, uint96 y) external {
        uint256 n = uint256(x) % (10 ether) + 1;
        uint256 m = uint256(y) % (10 ether) + 1;
        uint256 allowanceStart = n + m + 1 ether;
        uint256 total = token.totalSupply();
        vm.prank(A);
        require(token.approve(S, allowanceStart), "D24C_STATEFUL_APPROVE");
        require(token.allowance(A, S) == allowanceStart, "D24C_STATEFUL_INITIAL");
        vm.prank(S);
        require(token.transferFrom(A, B, n), "D24C_STATEFUL_SPEND1");
        require(token.allowance(A, S) == allowanceStart-n, "D24C_STATEFUL_DEBIT1");
        vm.prank(S);
        require(token.transferFrom(A, B, m), "D24C_STATEFUL_SPEND2");
        require(token.allowance(A, S) == 1 ether, "D24C_STATEFUL_DEBIT2");
        require(token.totalSupply() == total, "D24C_STATEFUL_SUPPLY");
        ++spends;
        ++checks;
    }

    function transferRoundTrip(uint96 seed) external {
        uint256 n = uint256(seed) % (10 ether) + 1;
        uint256 total = token.totalSupply();
        vm.prank(A);
        require(token.transfer(B, n), "D24C_STATEFUL_TRANSFER1");
        require(token.totalSupply() == total, "D24C_STATEFUL_CYCLE1");
        uint256 balance = token.balanceOf(B);
        require(balance > 0, "D24C_STATEFUL_ZERO_RECEIPT");
        vm.prank(B);
        require(token.transfer(A, balance), "D24C_STATEFUL_TRANSFER2");
        require(token.totalSupply() == total, "D24C_STATEFUL_CYCLE2");
        ++returns;
        ++checks;
    }
}

contract D24CStatefulReferenceTest is Test {
    ID24CAsset internal token;
    D24CStatefulHandler internal handler;
    uint256 internal originalSupply;
    function setUp() public {
        D24CAdapter environment = new D24CAdapter();
        token = ID24CAsset(environment.assetAddress());
        environment.mint(0, 1000 ether);
        originalSupply = token.totalSupply();
        handler = new D24CStatefulHandler(token);
        targetContract(address(handler));
    }
    function invariant_SupplyConsistentAcrossActions() public view {
        require(token.totalSupply() == originalSupply, "D24C_GLOBAL_SUPPLY");
    }
    function afterInvariant() public view {
        require(handler.checks() > 0, "D24C_VACUOUS_STATEFUL");
        require(handler.spends() > 0, "D24C_NO_ALLOWANCE_STEPS");
        require(handler.returns() > 0, "D24C_NO_ROUNDTRIP_STEPS");
    }
}
