// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {D21Setup} from "./D21Setup.sol";
import {CreditTrader, SpotPricePool, CollateralCustody, LendingMarket}
    from "../src/LocalLending.sol";

/// @notice A true multi-call Foundry invariant handler, independent of PRISM.
/// Its ABI is given to the Foundry stateful fuzzer via targetContracts().
contract D21StatefulHandler {
    CreditTrader public immutable trader;
    SpotPricePool public immutable pool;
    CollateralCustody public immutable custody;
    LendingMarket public immutable market;
    uint256 public attempted;
    uint256 public completed;

    constructor(CreditTrader t, SpotPricePool p,
                CollateralCustody c, LendingMarket m) {
        trader = t;
        pool = p;
        custody = c;
        market = m;
    }

    function pump(uint8 seed) external {
        ++attempted;
        uint256 amount = seed % 2 == 0 ? 50 : 100;
        try trader.pump(pool, amount) { ++completed; } catch { }
    }

    function pledge(uint8 seed) external {
        ++attempted;
        uint256 amount = seed % 3 == 0 ? 10 : (seed % 3 == 1 ? 20 : 40);
        try trader.pledge(custody, amount) { ++completed; } catch { }
    }

    function borrow(uint8 seed) external {
        ++attempted;
        uint256 amount = 10 * (1 + (uint256(seed) % 6));
        try trader.borrow(market, amount) { ++completed; } catch { }
    }

    function unwind(uint8 seed) external {
        ++attempted;
        uint256 amount = seed % 2 == 0 ? 25 : 50;
        try trader.unwind(pool, amount) { ++completed; } catch { }
    }
}

/// @notice Foundry's native invariant runner introspects targetContracts().
/// Unlike one-shot testFuzz, generated actions accumulate state for multiple
/// calls on the SAME deployed pool, custody and market.
abstract contract D21StatefulBase is D21Setup {
    D21StatefulHandler internal handler;

    function setUpVariant(bool guarded) internal {
        deploy(guarded);
        handler = new D21StatefulHandler(trader, pool, custody, lender);
    }

    function targetContracts() external view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function invariant_CollateralAndQuoteConserved() external view {
        assertConservation();
    }

    function invariant_FairCreditAtReferencePrice() external view {
        assertFairCredit();
    }
}

contract D21StatefulVulnerableTest is D21StatefulBase {
    function setUp() public { setUpVariant(false); }
}

contract D21StatefulGuardedTest is D21StatefulBase {
    function setUp() public { setUpVariant(true); }
}
