// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    CreditToken, SpotPricePool, CollateralCustody, LendingMarket, CreditTrader
} from "../src/LocalLending.sol";

/// @notice All participants and balances are local. No mainnet fork or funds.
abstract contract D21Setup {
    CreditToken internal collateral;
    CreditToken internal quote;
    SpotPricePool internal pool;
    CollateralCustody internal custody;
    LendingMarket internal lender;
    CreditTrader internal trader;

    function deploy(bool guarded) internal {
        collateral = new CreditToken();
        quote = new CreditToken();
        pool = new SpotPricePool(collateral, quote);
        custody = new CollateralCustody(collateral);
        lender = new LendingMarket(quote, custody, pool, guarded);
        trader = new CreditTrader(collateral, quote, pool, custody);

        collateral.mint(address(pool), 100);
        quote.mint(address(pool), 100);
        quote.mint(address(lender), 500);
        collateral.mint(address(trader), 100);
        quote.mint(address(trader), 200);
    }

    function assertConservation() internal view {
        require(quote.balanceOf(address(trader))
                + quote.balanceOf(address(pool))
                + quote.balanceOf(address(lender)) == 800, "quote not conserved");
        require(collateral.balanceOf(address(trader))
                + collateral.balanceOf(address(pool))
                + collateral.balanceOf(address(custody)) == 200, "collateral not conserved");
        require(custody.locked(address(trader))
                == collateral.balanceOf(address(custody)), "custody mismatch");
    }

    function assertFairCredit() internal view {
        uint256 locked = custody.locked(address(trader));
        require(lender.debt(address(trader)) <= locked * 75 / 100,
                "D21_FAIR_LTV_WITNESS");
    }
}
