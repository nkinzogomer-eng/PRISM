// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Isolated laboratory components. No real ERC20, no blockchain funds.
contract D22Coin {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address account, uint256 amount) external { balanceOf[account] += amount; }
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
    function transferFrom(address from, address to, uint256 amount) external {
        if (msg.sender != from) {
            require(allowance[from][msg.sender] >= amount, "insufficient allowance");
            allowance[from][msg.sender] -= amount;
        }
        require(balanceOf[from] >= amount, "insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract D22Oracle {
    address public immutable owner;
    bool public immutable ownerOnly;
    uint256 public price = 2;
    constructor(bool ownerOnly_) { owner = msg.sender; ownerOnly = ownerOnly_; }
    function update(uint256 value) external {
        require(value >= 1 && value <= 20, "invalid price");
        if (ownerOnly) require(msg.sender == owner, "not oracle admin");
        price = value;
    }
}

contract D22Credit {
    D22Coin public immutable collateralAsset;
    D22Coin public immutable loanAsset;
    D22Oracle public immutable oracle;
    bool public immutable debtSafeWithdraw;
    bool public immutable fundedRepay;
    mapping(address => uint256) public locked;
    mapping(address => uint256) public debt;

    constructor(D22Coin collateral_, D22Coin loan_, D22Oracle oracle_,
                bool withdrawSafe, bool repaySafe) {
        collateralAsset = collateral_;
        loanAsset = loan_;
        oracle = oracle_;
        debtSafeWithdraw = withdrawSafe;
        fundedRepay = repaySafe;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero deposit");
        collateralAsset.transferFrom(msg.sender, address(this), amount);
        locked[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        require(amount > 0, "zero borrow");
        require(debt[msg.sender] + amount <= limit(msg.sender), "not collateralized");
        debt[msg.sender] += amount;
        loanAsset.transfer(msg.sender, amount);
    }

    function limit(address account) public view returns (uint256) {
        return locked[account] * oracle.price() / 2;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0 && locked[msg.sender] >= amount, "bad withdrawal");
        uint256 remaining = locked[msg.sender] - amount;
        if (debtSafeWithdraw) {
            require(debt[msg.sender] <= remaining * oracle.price() / 2, "would be insolvent");
        }
        locked[msg.sender] = remaining;
        collateralAsset.transfer(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        require(amount > 0 && debt[msg.sender] >= amount, "bad repayment");
        if (fundedRepay) {
            loanAsset.transferFrom(msg.sender, address(this), amount);
        }
        // Variant without fundedRepay incorrectly forgives debt for free.
        debt[msg.sender] -= amount;
    }
}

contract D22Actor {
    function deposit(D22Coin collateral, D22Credit credit, uint256 amount) external {
        collateral.approve(address(credit), amount);
        credit.deposit(amount);
    }
    function borrow(D22Credit credit, uint256 amount) external { credit.borrow(amount); }
    function withdraw(D22Credit credit, uint256 amount) external { credit.withdraw(amount); }
    function repay(D22Coin loan, D22Credit credit, uint256 amount) external {
        loan.approve(address(credit), amount);
        credit.repay(amount);
    }
    function changePrice(D22Oracle oracle, uint256 amount) external { oracle.update(amount); }
}
