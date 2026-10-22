// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LocalAsset, LocalVault, LocalActor} from "../src/VaultFixture.sol";

/// @notice Deliberately FAILING conventional Foundry fuzz baseline.
/// Run separately from passing regressions; a failing fuzz counterexample is
/// evidence that conventional fuzzing can find this same known issue.
contract FuzzBaselineTest {
    function testFuzzUnguardedMustMintShares(
        uint8 attackerSeed, uint8 donationSeed, uint8 victimSeed
    ) external {
        LocalAsset token = new LocalAsset();
        LocalVault vault = new LocalVault(token, false);
        LocalActor attacker = new LocalActor();
        LocalActor victim = new LocalActor();

        token.mint(address(attacker), 500);
        token.mint(address(victim), 500);
        attacker.approveVault(token, vault);
        victim.approveVault(token, vault);

        uint256 attackerAmount = uint256(attackerSeed % 100) + 1;
        uint256 gift = uint256(donationSeed % 100) + 1;
        uint256 victimAmount = uint256(victimSeed % 100) + 1;

        attacker.deposit(vault, attackerAmount);
        attacker.donate(token, vault, gift);
        uint256 minted = victim.deposit(vault, victimAmount);

        // A generic financial safety property: positive successful deposit
        // must not produce zero shares. This test SHOULD FAIL on vulnerable.
        require(minted > 0, "D20_ZERO_SHARE_WITNESS");
    }
}

/// @notice The patched variant must not silently accept a zero-share mint.
contract FuzzPatchedControlTest {
    function testFuzzPatchedNeverAcceptsZeroShares(
        uint8 attackerSeed, uint8 donationSeed, uint8 victimSeed
    ) external {
        LocalAsset token = new LocalAsset();
        LocalVault vault = new LocalVault(token, true);
        LocalActor attacker = new LocalActor();
        LocalActor victim = new LocalActor();

        token.mint(address(attacker), 500);
        token.mint(address(victim), 500);
        attacker.approveVault(token, vault);
        victim.approveVault(token, vault);

        uint256 attackerAmount = uint256(attackerSeed % 100) + 1;
        uint256 gift = uint256(donationSeed % 100) + 1;
        uint256 victimAmount = uint256(victimSeed % 100) + 1;

        attacker.deposit(vault, attackerAmount);
        attacker.donate(token, vault, gift);
        uint256 beforeVictim = token.balanceOf(address(victim));
        try victim.deposit(vault, victimAmount) returns (uint256 minted) {
            require(minted > 0, "guard-accepted-zero-shares");
            require(token.balanceOf(address(victim)) == beforeVictim - victimAmount,
                    "guarded-deposit-not-debited");
        } catch {
            require(token.balanceOf(address(victim)) == beforeVictim,
                    "guarded-failed-deposit-debited");
        }
    }
}
