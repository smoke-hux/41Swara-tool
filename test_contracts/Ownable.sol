// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Ownable {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Vulnerable: No two-step ownership transfer
    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}