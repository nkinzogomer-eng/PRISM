// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Research-only token, NOT ERC-20 compliant. No real asset or deployment.
contract DemoAsset {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient-asset");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
    function transferFrom(address from, address to, uint256 amount) external {
        require(msg.sender == from || allowance[from][msg.sender] >= amount, "allowance");
        if (msg.sender != from) allowance[from][msg.sender] -= amount;
        require(balanceOf[from] >= amount, "insufficient-asset");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 amount) external { allowance[msg.sender][spender] = amount; }
}

/// @dev Multi-contract laboratory property: only owner may modify price when guarded.
contract DemoPriceOracle {
    uint256 public price;
    address public owner;
    bool public immutable guarded;
    constructor(bool secure, uint256 initialPrice) {
        owner = msg.sender;
        guarded = secure;
        price = initialPrice;
    }
    function setPrice(uint256 value) external {
        require(value > 0 && value <= 100, "bad-price");
        if (guarded) require(msg.sender == owner, "unauthorized-price");
        price = value;
    }
}

/// @dev Simple collateral-backed lending: no interest, no liquidations, no real token support.
contract DemoLender {
    DemoAsset public immutable collateralToken;
    DemoAsset public immutable debtToken;
    DemoPriceOracle public immutable oracle;
    mapping(address => uint256) public deposited;
    mapping(address => uint256) public debt;
    constructor(DemoAsset collateral_, DemoAsset debt_, DemoPriceOracle oracle_) {
        collateralToken = collateral_;
        debtToken = debt_;
        oracle = oracle_;
    }
    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        collateralToken.transferFrom(msg.sender, address(this), amount);
        deposited[msg.sender] += amount;
    }
    function borrow(uint256 amount) external {
        require(amount > 0, "zero");
        require(debt[msg.sender] + amount <= deposited[msg.sender] * oracle.price() / 2,
                "ltv-exceeded");
        debt[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
    function currentBorrowLimit(address account) external view returns (uint256) {
        return deposited[account] * oracle.price() / 2;
    }
}

/// @dev Actor contract ensures oracle call originates from attacker, not admin test contract.
contract DemoTrader {
    function approveAndDeposit(DemoAsset collateral, DemoLender lender, uint256 amount) external {
        collateral.approve(address(lender), amount);
        lender.deposit(amount);
    }
    function alterPrice(DemoPriceOracle oracle, uint256 price) external { oracle.setPrice(price); }
    function takeLoan(DemoLender lender, uint256 amount) external { lender.borrow(amount); }
}
