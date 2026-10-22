// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice D2.1 laboratory only. No real assets, no permission model, no production safety.
contract CreditToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address dst, uint256 n) external {
        balanceOf[dst] += n;
    }
    function approve(address spender, uint256 n) external returns (bool) {
        allowance[msg.sender][spender] = n;
        return true;
    }
    function transfer(address dst, uint256 n) external returns (bool) {
        require(balanceOf[msg.sender] >= n, "insufficient");
        balanceOf[msg.sender] -= n;
        balanceOf[dst] += n;
        return true;
    }
    function transferFrom(address src, address dst, uint256 n) external returns (bool) {
        require(balanceOf[src] >= n && allowance[src][msg.sender] >= n, "transferFrom");
        allowance[src][msg.sender] -= n;
        balanceOf[src] -= n;
        balanceOf[dst] += n;
        return true;
    }
}

/// @notice Simplified fee-free constant-product spot-price source, *not* a real AMM.
/// Mint reserves into this contract before invoking swaps.
contract SpotPricePool {
    CreditToken public immutable collateral;
    CreditToken public immutable quote;
    uint256 public reserveCollateral = 100;
    uint256 public reserveQuote = 100;

    constructor(CreditToken c, CreditToken q) {
        collateral = c;
        quote = q;
    }

    function spotPriceTimes100() external view returns (uint256) {
        return reserveQuote * 100 / reserveCollateral;
    }

    function pump(uint256 quoteIn) external returns (uint256 collateralOut) {
        require(quoteIn > 0 && reserveCollateral > 1, "invalid pump");
        uint256 newQ = reserveQuote + quoteIn;
        uint256 newC = reserveQuote * reserveCollateral / newQ;
        require(newC > 0 && newC < reserveCollateral, "no swap output");
        collateralOut = reserveCollateral - newC;
        require(quote.transferFrom(msg.sender, address(this), quoteIn), "q payment");
        require(collateral.transfer(msg.sender, collateralOut), "c received");
        reserveQuote = newQ;
        reserveCollateral = newC;
        require(quote.balanceOf(address(this)) == newQ, "q reserves");
        require(collateral.balanceOf(address(this)) == newC, "c reserves");
    }

    function unwind(uint256 collateralIn) external returns (uint256 quoteOut) {
        require(collateralIn > 0, "invalid unwind");
        uint256 newC = reserveCollateral + collateralIn;
        uint256 newQ = reserveQuote * reserveCollateral / newC;
        require(newQ > 0 && newQ < reserveQuote, "no swap output");
        quoteOut = reserveQuote - newQ;
        require(collateral.transferFrom(msg.sender, address(this), collateralIn),
                "c payment");
        require(quote.transfer(msg.sender, quoteOut), "q received");
        reserveCollateral = newC;
        reserveQuote = newQ;
        require(quote.balanceOf(address(this)) == newQ, "q reserves");
        require(collateral.balanceOf(address(this)) == newC, "c reserves");
    }
}

/// @notice Separate module: custody is distinct from the lending market.
contract CollateralCustody {
    CreditToken public immutable collateral;
    mapping(address => uint256) public locked;
    constructor(CreditToken c) { collateral = c; }

    function pledge(uint256 n) external {
        require(n > 0, "empty pledge");
        require(collateral.transferFrom(msg.sender, address(this), n), "pledge transfer");
        locked[msg.sender] += n;
    }
}

/// @notice Price-dependent credit is the deliberately vulnerable variant.
/// Guarded variant uses a stable independent laboratory reference of 1 quote
/// unit per collateral, NOT a general solution for real-world lending.
contract LendingMarket {
    CreditToken public immutable quote;
    CollateralCustody public immutable custody;
    SpotPricePool public immutable pool;
    bool public immutable anchoredPrice;
    mapping(address => uint256) public debt;

    constructor(CreditToken q, CollateralCustody c, SpotPricePool p, bool guarded) {
        quote = q;
        custody = c;
        pool = p;
        anchoredPrice = guarded;
    }

    function creditLimit(address user) public view returns (uint256) {
        uint256 price100 = anchoredPrice ? 100 : pool.spotPriceTimes100();
        return custody.locked(user) * price100 * 75 / 10_000; // LTV 75%
    }

    function borrow(uint256 n) external {
        require(n > 0 && debt[msg.sender] + n <= creditLimit(msg.sender),
                "collateral limit");
        debt[msg.sender] += n;
        require(quote.transfer(msg.sender, n), "no quote liquidity");
    }
}

contract CreditTrader {
    constructor(CreditToken c, CreditToken q,
                SpotPricePool pool, CollateralCustody custody) {
        c.approve(address(pool), type(uint256).max);
        q.approve(address(pool), type(uint256).max);
        c.approve(address(custody), type(uint256).max);
    }

    function pump(SpotPricePool pool, uint256 n) external { pool.pump(n); }
    function pledge(CollateralCustody custody, uint256 n) external {
        custody.pledge(n);
    }
    function borrow(LendingMarket market, uint256 n) external { market.borrow(n); }
    function unwind(SpotPricePool pool, uint256 n) external { pool.unwind(n); }
}
