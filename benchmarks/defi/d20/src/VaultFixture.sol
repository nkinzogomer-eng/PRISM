// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Local-only toy asset: NOT production ERC20. No financial value.
contract LocalAsset {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount)
        external returns (bool)
    {
        require(balanceOf[sender] >= amount, "balance");
        require(allowance[sender][msg.sender] >= amount, "allowance");
        allowance[sender][msg.sender] -= amount;
        balanceOf[sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

/// @notice Minimal vault used exclusively to test share-accounting invariants.
/// The variant flag is private in the benchmark's detector-facing copy.
contract LocalVault {
    LocalAsset public immutable asset;
    bool public immutable rejectZeroShares;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(LocalAsset token, bool rejectEmptyMint) {
        asset = token;
        rejectZeroShares = rejectEmptyMint;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero assets");
        uint256 beforeAssets = asset.balanceOf(address(this));
        if (totalSupply == 0) {
            shares = assets;
        } else {
            require(beforeAssets > 0, "empty vault");
            shares = assets * totalSupply / beforeAssets;
        }
        // This guard distinguishes the two locally controlled variants.
        // The unguarded version silently accepts deposits minting zero shares.
        if (rejectZeroShares) require(shares > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets), "payment");
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && shares <= balanceOf[msg.sender], "shares");
        uint256 supply = totalSupply;
        assets = shares * asset.balanceOf(address(this)) / supply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        require(asset.transfer(msg.sender, assets), "transfer");
    }
}

/// @notice Two actors ensure distinct msg.sender in Foundry without libraries.
contract LocalActor {
    function approveVault(LocalAsset token, LocalVault vault) external {
        token.approve(address(vault), type(uint256).max);
    }

    function deposit(LocalVault vault, uint256 amount)
        external returns (uint256 shares)
    {
        return vault.deposit(amount);
    }

    function donate(LocalAsset token, LocalVault vault, uint256 amount) external {
        require(token.transfer(address(vault), amount), "donate");
    }

    function redeemAll(LocalVault vault) external returns (uint256 assets) {
        return vault.redeem(vault.balanceOf(address(this)));
    }
}
