// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract TestVersion27 {
    uint256 public value;
    
    constructor() public {  // Testing constructor visibility warning
        value = 100;
    }
    
    function setValue(uint256 _value) public {
        value = _value;
    }
}