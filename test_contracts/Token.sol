// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Ownable.sol";

contract Token is Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    // Vulnerable: No access control
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }
    
    // Vulnerable: Reentrancy
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        (bool success,) = msg.sender.call{value: balance}("");
        require(success);
        balances[msg.sender] = 0; // State change after external call
    }
    
    // Vulnerable: Integer overflow in older versions
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}