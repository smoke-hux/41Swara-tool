// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract TestContract {
    uint256 public balance;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transfer(address to, uint256 amount) external {
        // This would be caught as missing access control
        balance -= amount;
        
        // Unchecked block - should be detected in 0.8.0+
        unchecked {
            uint256 result = amount + 100;
            balance = result;
        }
    }
    
    // Using block.timestamp for randomness - should be detected
    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
    }
}