// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

contract TestVersion29 {
    uint256 public value;
    
    function expensiveOperation() public {
        // This version has memory expansion cost miscalculation issues
        uint256[] memory largeArray = new uint256[](1000);
        for (uint i = 0; i < largeArray.length; i++) {
            largeArray[i] = i;
        }
    }
}