// SPDX-License-Identifier: MIT
// EXPECT: Reentrancy
// VULN CORPUS CASE — classic single-function reentrancy.
pragma solidity 0.8.24;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");

        // VULNERABLE: external call BEFORE the balance is zeroed. A malicious
        // receiver re-enters `withdraw` and drains the contract.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] -= amount;
    }

    function drainAll() external {
        uint256 amount = balances[msg.sender];
        // VULNERABLE: same interactions-before-effects ordering.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
