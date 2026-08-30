// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Layout {
    bool public flag;                             // slot 0, offset 0  (1 byte)
    uint8 public small;                           // slot 0, offset 1  (1 byte)
    address public owner;                         // slot 0, offset 2  (20 bytes)
    uint256 public total;                         // slot 1
    mapping(address => uint256) public balances;  // slot 2 (own slot)
    uint8 public tail;                            // slot 3 (mapping forces a new slot)

    uint256 public constant MAX = 100;            // no slot
    address public immutable deployer;            // no slot

    constructor() {
        deployer = msg.sender;
    }
}
