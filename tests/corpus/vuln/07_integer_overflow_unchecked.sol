// SPDX-License-Identifier: MIT
// EXPECT: ArithmeticIssues
// VULN CORPUS CASE — arithmetic wrapped in `unchecked` with no guard, plus a
// legacy floating pragma that allows a pre-0.8 compiler with no checked math.
pragma solidity ^0.7.6;

contract OverflowBank {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit() public payable {
        // VULNERABLE: pre-0.8.0 has no overflow checks and no SafeMath is used.
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) public {
        // VULNERABLE: underflows to a huge number when amount > balance.
        balances[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }

    function batchTransfer(address[] memory receivers, uint256 value) public {
        // VULNERABLE: `receivers.length * value` overflows, making `amount`
        // small enough to pass the balance check while crediting huge values.
        uint256 amount = receivers.length * value;
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
    }
}
