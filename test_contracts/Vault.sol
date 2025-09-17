// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Token.sol";

contract Vault {
    Token public token;
    mapping(address => uint256) public deposits;
    
    constructor(address _token) {
        token = Token(_token);
    }
    
    // Vulnerable: No checks for zero address
    function deposit(uint256 amount) external {
        token.transfer(address(this), amount);
        deposits[msg.sender] += amount;
    }
    
    // Vulnerable: External call without reentrancy guard
    function withdrawAll() external {
        uint256 balance = deposits[msg.sender];
        deposits[msg.sender] = 0;
        
        // External call
        token.transfer(msg.sender, balance);
    }
    
    // Vulnerable: Using block.timestamp
    function timedWithdraw() external {
        require(block.timestamp > 1000000, "Too early");
        withdrawAll();
    }
}