// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title Safe contract with ReentrancyGuard — should produce 0 Critical/High reentrancy findings
contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function withdrawAll() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Transfer failed");
    }
}
