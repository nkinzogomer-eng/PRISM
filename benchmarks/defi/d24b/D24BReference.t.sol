// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {D24BAdapter, ID24BAsset} from "./D24BAdapter.sol";

/// @notice Independently authored *stateful* baseline on the same compiled
/// upstream Origin Dollar implementation. It uses the same public ERC20
/// conservation requirement, NOT PRISM-generated transaction traces.
/// Properties given to both approaches, no labeled historical exploit input.
contract D24BTransferHandler is Test {
    ID24BAsset public immutable asset;
    uint256 public successes;
    uint256 public attempts;
    constructor(ID24BAsset a) { asset = a; }

    function move(uint96 seed, bool reverse) external {
        ++attempts;
        address sender = reverse ? address(0x40000) : address(0x30000);
        address recipient = reverse ? address(0x30000) : address(0x40000);
        uint256 balance = asset.balanceOf(sender);
        if (balance == 0) return;
        uint256 amount = uint256(seed) % balance + 1;
        vm.prank(sender);
        try asset.transfer(recipient, amount) returns (bool ok) {
            if (ok) ++successes;
        } catch {}
    }

    function allow(uint96 seed) external {
        ++attempts;
        vm.prank(address(0x30000));
        try asset.approve(address(0x40000), uint256(seed)) returns (bool ok) {
            if (ok) {
                ++successes;
                require(asset.allowance(address(0x30000), address(0x40000)) ==
                        uint256(seed), "D24B_BASELINE_APPROVE_MISMATCH");
            }
        } catch {}
    }
}

contract D24BStatefulReferenceTest is Test {
    D24BAdapter internal tester;
    ID24BAsset internal asset;
    D24BTransferHandler internal handler;
    uint256 internal initialSupply;

    function setUp() public {
        tester = new D24BAdapter();
        asset = ID24BAsset(tester.assetAddress());
        // A one-time mint in setup; NO rebases, mint or burn in the handler.
        tester.mint(0, 1000 ether);
        initialSupply = asset.totalSupply();
        handler = new D24BTransferHandler(asset);
        targetContract(address(handler));
    }

    function invariant_SupplyUnchangedForTransferAndApproval() public view {
        require(asset.totalSupply() == initialSupply,
                "D24B_BASELINE_SUPPLY_DRIFT");
    }
}
