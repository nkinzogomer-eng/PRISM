// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {D21Setup} from "./D21Setup.sol";

/// @notice Independent behavioral fixture; does not use PRISM search output.
contract D21BehaviorTest is D21Setup {
    function testTradeAndCollateralConservation() external {
        deploy(false);
        uint256 acquired = pool.spotPriceTimes100();
        require(acquired == 100, "initial spot price");
        trader.pump(pool, 100);
        require(pool.reserveQuote() == 200, "pool quote after pump");
        require(pool.reserveCollateral() == 50, "pool collateral after pump");
        require(pool.spotPriceTimes100() == 400, "spot price not pumped");
        trader.unwind(pool, 50);
        require(pool.reserveQuote() == 100, "quote not restored");
        require(pool.reserveCollateral() == 100, "collateral not restored");
        assertConservation();
    }

    function testNormalLegitimateLoanBothModes() external {
        for (uint256 i = 0; i < 2; i++) {
            deploy(i == 1);
            trader.pledge(custody, 20);
            trader.borrow(lender, 10);
            require(lender.debt(address(trader)) == 10, "legitimate loan absent");
            assertFairCredit();
            assertConservation();
        }
    }

    function testVulnerablePriceInflationAllowsUnsafeCredit() external {
        deploy(false);
        trader.pump(pool, 100);
        trader.pledge(custody, 20);
        trader.borrow(lender, 60);
        trader.unwind(pool, 50);
        require(lender.debt(address(trader)) == 60, "missing debt");
        require(custody.locked(address(trader)) == 20, "wrong collateral");
        require(pool.reserveQuote() == 100 && pool.reserveCollateral() == 100,
                "spot not restored");
        require(quote.balanceOf(address(trader)) == 260, "wrong quote cash");
        require(collateral.balanceOf(address(trader)) == 80, "wrong collateral cash");
        require(lender.debt(address(trader)) > 20 * 75 / 100,
                "expected reference credit breach");
        assertConservation();
    }

    function testIndependentGuardRefusesOverLoan() external {
        deploy(true);
        trader.pump(pool, 100);
        trader.pledge(custody, 20);
        uint256 quoteBefore = quote.balanceOf(address(trader));
        bool refused = false;
        try trader.borrow(lender, 60) { } catch { refused = true; }
        require(refused, "guard must refuse");
        require(quote.balanceOf(address(trader)) == quoteBefore, "guard debited quote");
        require(lender.debt(address(trader)) == 0, "guard recorded debt");
        assertFairCredit();
        assertConservation();
    }
}

/// @notice Conventional property-based fuzz controls, independent of D2.1 planner.
/// This is a deliberately *fair* baseline and may detect the defect itself.
contract D21FuzzVulnerableTest is D21Setup {
    function testFuzzReferenceLTV(uint8 spotSeed, uint8 pledgeSeed, uint8 borrowSeed)
        external
    {
        deploy(false);
        uint256 payment = 1 + uint256(spotSeed % 100);
        uint256 coll = 1 + uint256(pledgeSeed % 40);
        uint256 ask = 1 + uint256(borrowSeed % 100);
        trader.pump(pool, payment);
        trader.pledge(custody, coll);
        try trader.borrow(lender, ask) {
            // A fair reference valuation, *not* the same manipulated spot.
            assertFairCredit();
        } catch {
            // Borrow not approved; cannot be classified a violation.
        }
        assertConservation();
    }
}

contract D21FuzzGuardedTest is D21Setup {
    function testFuzzReferenceLTV(uint8 spotSeed, uint8 pledgeSeed, uint8 borrowSeed)
        external
    {
        deploy(true);
        uint256 payment = 1 + uint256(spotSeed % 100);
        uint256 coll = 1 + uint256(pledgeSeed % 40);
        uint256 ask = 1 + uint256(borrowSeed % 100);
        trader.pump(pool, payment);
        trader.pledge(custody, coll);
        try trader.borrow(lender, ask) { assertFairCredit(); } catch { }
        assertConservation();
    }
}
