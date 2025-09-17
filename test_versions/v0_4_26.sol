// SPDX-License-Identifier: MIT
pragma solidity 0.4.26;

contract OldVersion {
    uint256 public value;
    
    // Old constructor style (vulnerable)
    function OldVersion() public {
        value = 0;
    }
    
    function setValue(uint256 _value) public {
        // No automatic overflow protection
        value = _value + 1;
    }
}