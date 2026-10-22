// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LocalAsset, LocalVault, LocalActor} from "../src/VaultFixture.sol";

/// @notice Independent local EVM behavioral oracle; NOT a detector.
contract VaultBehaviorTest {
    function _setup(bool guarded)
        internal returns (LocalAsset token, LocalVault vault, LocalActor attacker, LocalActor victim)
    {
        token = new LocalAsset();
        vault = new LocalVault(token, guarded);
        attacker = new LocalActor();
        victim = new LocalActor();
        token.mint(address(attacker), 200);
        token.mint(address(victim), 200);
        attacker.approveVault(token, vault);
        victim.approveVault(token, vault);
    }

    function testUnguardedVaultCanAcceptZeroShareDeposit() external {
        (LocalAsset token, LocalVault vault, LocalActor attacker, LocalActor victim) = _setup(false);
        attacker.deposit(vault, 1);
        attacker.donate(token, vault, 10);
        uint256 victimShares = victim.deposit(vault, 1);
        require(victimShares == 0, "expected zero-share acceptance");
        attacker.redeemAll(vault);
        require(token.balanceOf(address(attacker)) > 200, "no attacker profit");
        require(token.balanceOf(address(victim)) < 200, "no victim loss");
    }

    function testGuardedVaultRejectsZeroShareDeposit() external {
        (LocalAsset token, LocalVault vault, LocalActor attacker, LocalActor victim) = _setup(true);
        attacker.deposit(vault, 1);
        attacker.donate(token, vault, 10);
        bool reverted = false;
        try victim.deposit(vault, 1) returns (uint256 shares) {
            require(shares > 0, "accepted zero shares");
        } catch {
            reverted = true;
        }
        require(reverted, "guard did not reject");
        require(token.balanceOf(address(victim)) == 200, "victim lost funds");
    }

    function testNormalFlowWorksOnBothVersions() external {
        for (uint256 i = 0; i < 2; ++i) {
            (LocalAsset token, LocalVault vault, LocalActor alice, LocalActor bob) = _setup(i == 1);
            uint256 a = alice.deposit(vault, 20);
            uint256 b = bob.deposit(vault, 20);
            require(a == 20 && b == 20, "ordinary deposits");
            require(alice.redeemAll(vault) == 20, "alice redemption");
            require(bob.redeemAll(vault) == 20, "bob redemption");
            require(token.balanceOf(address(alice)) == 200, "alice funds");
            require(token.balanceOf(address(bob)) == 200, "bob funds");
        }
    }
}
