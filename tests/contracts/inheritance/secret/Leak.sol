// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Leaked {
    modifier leakedModifier() { require(msg.sender != address(0)); _; }
}
