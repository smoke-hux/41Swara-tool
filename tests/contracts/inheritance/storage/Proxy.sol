// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MyProxy {
    address public implementation;   // slot 0
    address public admin;            // slot 0, offset 20
    uint256 public version;          // slot 1
}

contract MyImpl {
    uint256 public totalSupply;      // slot 0  <-- collides with `implementation`
    address public treasury;         // slot 1
}
