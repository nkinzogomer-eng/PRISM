// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {DemoAsset, DemoPriceOracle, DemoLender, DemoTrader} from "../src/LendingFixture.sol";

/// @notice Conventional independent parameter fuzz with the exact same solvency
/// property. This baseline deliberately FAILS on the insecure oracle.
/// This is NOT stateful handler fuzz, symbolic execution, or a comprehensive audit.
contract D21ConventionalFuzzBaselineTest {
    function testFuzzUnsafePriceOracleViolatesDebtLimit(uint8 collateralSeed, uint8 priceSeed) external {
        DemoAsset collateral = new DemoAsset();
        DemoAsset stable = new DemoAsset();
        DemoPriceOracle oracle = new DemoPriceOracle(false, 2);
        DemoLender lender = new DemoLender(collateral, stable, oracle);
        DemoTrader borrower = new DemoTrader();
        collateral.mint(address(borrower), 100);
        stable.mint(address(lender), 1000);
        uint256 quantity = uint256(collateralSeed % 20) + 1;
        uint256 pumped = uint256(priceSeed % 15) + 4;
        borrower.approveAndDeposit(collateral, lender, quantity);
        borrower.alterPrice(oracle, pumped);
        borrower.takeLoan(lender, quantity * pumped / 2);
        borrower.alterPrice(oracle, 2);
        require(lender.debt(address(borrower)) <= lender.currentBorrowLimit(address(borrower)),
                "D21_UNDERCOLLATERALIZED");
    }
}

contract D21GuardedFuzzControlTest {
    function testFuzzUnauthorizedPriceChangeCannotBreakLimit(uint8 collateralSeed, uint8 priceSeed) external {
        DemoAsset collateral = new DemoAsset();
        DemoAsset stable = new DemoAsset();
        DemoPriceOracle oracle = new DemoPriceOracle(true, 2);
        DemoLender lender = new DemoLender(collateral, stable, oracle);
        DemoTrader borrower = new DemoTrader();
        collateral.mint(address(borrower), 100);
        stable.mint(address(lender), 1000);
        borrower.approveAndDeposit(collateral, lender, uint256(collateralSeed % 20) + 1);
        bool rejected;
        try borrower.alterPrice(oracle, uint256(priceSeed % 15) + 4) {
            rejected = false;
        } catch {
            rejected = true;
        }
        require(rejected, "price-permission-missing");
        require(oracle.price() == 2, "oracle-drifted");
        require(lender.debt(address(borrower)) <= lender.currentBorrowLimit(address(borrower)),
                "patched-safety-violated");
    }
}
