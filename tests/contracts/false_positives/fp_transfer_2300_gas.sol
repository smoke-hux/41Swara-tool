// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title .transfer()/.send() with 2300 gas — safe from reentrancy (should not flag reentrancy)
contract SafeTransferContract {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawTransfer(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount); // 2300 gas limit — safe from reentrancy
    }

    function withdrawSend(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        bool success = payable(msg.sender).send(amount); // 2300 gas limit
        require(success, "Send failed");
    }
}
