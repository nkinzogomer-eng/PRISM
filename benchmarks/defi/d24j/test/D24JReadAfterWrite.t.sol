// SPDX-License-Identifier: MIT
pragma solidity =0.5.16;

import "../src/UniswapV2Pair.sol";

/// @dev Isolated adversarial fixture token, not a production ERC20.
contract D24JFixtureToken {
    mapping(address => uint256) public balanceOf;

    function mint(address target, uint256 amount) external {
        require(amount <= 1000000, "fixture amount budget");
        balanceOf[target] += amount;
    }

    function burn(address target, uint256 amount) external {
        require(balanceOf[target] >= amount, "fixture burn requires funds");
        balanceOf[target] -= amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "fixture insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice Independent EVM read-after-write observer for PRISM-generated
/// getReserves/_update/sync relationship. It observes actual compiled
/// third-party Uniswap V2 pair code; not a Python simulation.
contract D24JReadAfterWriteTest {
    D24JFixtureToken internal first;
    D24JFixtureToken internal second;
    UniswapV2Pair internal pair;

    function setUp() public {
        first = new D24JFixtureToken();
        second = new D24JFixtureToken();
        pair = new UniswapV2Pair();
        pair.initialize(address(first), address(second));
    }

    function _assertReconciled() internal view {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        require(uint256(reserve0) == first.balanceOf(address(pair)), "observer: token0 mismatch");
        require(uint256(reserve1) == second.balanceOf(address(pair)), "observer: token1 mismatch");
    }

    function test_post_sync_reserves_reconcile_eight_external_mutations() public {
        for (uint256 i = 1; i <= 8; i++) {
            first.mint(address(pair), i * 7);
            second.mint(address(pair), i * 11);
            pair.sync();
            _assertReconciled();
        }
    }

    function test_external_balance_drift_is_observed_before_sync() public {
        first.mint(address(pair), 17);
        (uint112 oldReserve,,) = pair.getReserves();
        require(uint256(oldReserve) != first.balanceOf(address(pair)),
                "negative control failed: unrecorded deposit was invisible");
        pair.sync();
        _assertReconciled();
    }

    function test_post_sync_reconciles_burns_and_asymmetric_balances() public {
        first.mint(address(pair), 144);
        second.mint(address(pair), 89);
        pair.sync();
        _assertReconciled();
        first.burn(address(pair), 13);
        second.burn(address(pair), 89);
        pair.sync();
        _assertReconciled();
    }
}
