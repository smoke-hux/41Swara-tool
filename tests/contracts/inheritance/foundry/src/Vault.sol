// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice The canonical false-positive case: `onlyOwner` is defined in another file.
contract Vault is Ownable, ReentrancyGuard {
    mapping(address => uint256) public deposits;

    function sweep(address to, uint256 amount) external onlyOwner {
        deposits[to] -= amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        deposits[msg.sender] -= amount;
    }
}
