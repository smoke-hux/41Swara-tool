// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

contract TestOldVersion {
    uint256 public value;
    
    // This version has known issues with:
    // - Storage write reentrancy in libraries
    // - Optimizer bugs
    // - ABI coder issues
    
    function complexOperation(uint256[] memory data) public returns (uint256[] memory) {
        // ABI coder v2 issues with tuples in this version
        return data;
    }
    
    function unsafeCall(address target) public {
        // Vulnerable to reentrancy in libraries
        (bool success,) = target.call("");
        require(success);
    }
}