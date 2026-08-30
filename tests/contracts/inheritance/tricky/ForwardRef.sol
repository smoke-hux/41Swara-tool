// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UsesLater is DefinedLater {
    function f() external onlyLater {}
}

abstract contract DefinedLater {
    modifier onlyLater() {
        require(msg.sender == address(0x1));
        _;
    }
}
