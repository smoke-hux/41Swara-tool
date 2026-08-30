// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Crlf {
    modifier onlyCrlf() {
        require(msg.sender == address(0x1));
        _;
    }
    function f() external onlyCrlf {}
}