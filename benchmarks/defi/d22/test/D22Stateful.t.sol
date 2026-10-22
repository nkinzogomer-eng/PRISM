// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {D22Coin, D22Oracle, D22Credit, D22Actor} from "../src/MultiRisk.sol";

/// @notice Foundry independently generates multi-transaction stateful sequences.
/// It does NOT import or execute the Python PRISM search model.
contract D22StatefulHandler {
    D22Coin public immutable collateral;
    D22Coin public immutable loan;
    D22Oracle public immutable oracle;
    D22Credit public immutable market;
    D22Actor public immutable actor;
    bool public everUnfunded;
    uint256 public attempts;
    uint256 public successes;

    constructor(D22Coin c, D22Coin l, D22Oracle o, D22Credit m, D22Actor a) {
        collateral = c;
        loan = l;
        oracle = o;
        market = m;
        actor = a;
    }

    function deposit(uint8 seed) external {
        ++attempts;
        uint256 amount = seed % 2 == 0 ? 10 : 20;
        try actor.deposit(collateral, market, amount) { ++successes; } catch {}
    }

    function borrow(uint8 seed) external {
        ++attempts;
        uint256 amount = seed % 2 == 0 ? 10 : 100;
        try actor.borrow(market, amount) { ++successes; } catch {}
    }

    function withdraw(uint8 seed) external {
        ++attempts;
        uint256 amount = seed % 2 == 0 ? 10 : 20;
        try actor.withdraw(market, amount) { ++successes; } catch {}
    }

    function repay(uint8 seed) external {
        ++attempts;
        uint256 amount = seed % 2 == 0 ? 10 : 20;
        uint256 poolBefore = loan.balanceOf(address(market));
        uint256 borrowerBefore = loan.balanceOf(address(actor));
        uint256 debtBefore = market.debt(address(actor));
        try actor.repay(loan, market, amount) {
            ++successes;
            if (debtBefore > market.debt(address(actor))
                    && poolBefore == loan.balanceOf(address(market))
                    && borrowerBefore == loan.balanceOf(address(actor))) {
                everUnfunded = true;
            }
        } catch {}
    }

    function changePrice(uint8 seed) external {
        ++attempts;
        uint256 value = seed % 2 == 0 ? 20 : 3;
        try actor.changePrice(oracle, value) { ++successes; } catch {}
    }
}

/// @notice Foundry invariant runner uses this targetContracts() interface to
/// identify the handler and generate independent arbitrary CALL SEQUENCES.
/// We deliberately avoid forge-std dependency and assume no mainnet activity.
abstract contract D22StatefulBase {
    D22Coin internal collateral;
    D22Coin internal loan;
    D22Oracle internal oracle;
    D22Credit internal market;
    D22Actor internal actor;
    D22StatefulHandler internal handler;

    function setupVariant(uint8 variant) internal {
        collateral = new D22Coin();
        loan = new D22Coin();
        oracle = new D22Oracle(variant != 1);
        market = new D22Credit(collateral, loan, oracle, variant != 2, variant != 3);
        actor = new D22Actor();
        collateral.mint(address(actor), 100);
        loan.mint(address(actor), 100);
        loan.mint(address(market), 1000);
        handler = new D22StatefulHandler(collateral, loan, oracle, market, actor);
    }

    function targetContracts() external view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function invariant_TokenConservation() public view {
        require(collateral.balanceOf(address(actor)) +
                collateral.balanceOf(address(market)) == 100,
                "D22_COLLATERAL_CONSERVATION");
        require(loan.balanceOf(address(actor)) +
                loan.balanceOf(address(market)) == 1100,
                "D22_LOAN_CONSERVATION");
    }

    function invariant_OracleOwnerOnly() public view {
        require(oracle.price() == 2, "D22_ORACLE_AUTH_WITNESS");
    }

    function invariant_CollateralSolvent() public view {
        require(market.debt(address(actor)) <= market.limit(address(actor)),
                "D22_WITHDRAW_SOLVENCY_WITNESS");
    }

    function invariant_RepaymentFunded() public view {
        require(!handler.everUnfunded(), "D22_UNFUNDED_REPAY_WITNESS");
    }
}

// Each deliberate failure test exposes only the relevant invariant, alongside
// conservation. This avoids cross-label contamination among vulnerabilities.
contract D22OracleBugStatefulTest is D22StatefulBase {
    function setUp() public { setupVariant(1); }
    function invariant_OracleOwnerOnly() public view override {
        super.invariant_OracleOwnerOnly();
    }
}
contract D22WithdrawBugStatefulTest is D22StatefulBase {
    function setUp() public { setupVariant(2); }
}
contract D22RepayBugStatefulTest is D22StatefulBase {
    function setUp() public { setupVariant(3); }
}
contract D22AllSafeStatefulTest is D22StatefulBase {
    function setUp() public { setupVariant(0); }
}
