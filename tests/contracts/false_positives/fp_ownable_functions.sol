// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title Safe contract with proper access control — should produce 0 Critical/High access control findings
contract SafeAdmin is Ownable {
    uint256 public feeRate;
    address public oracle;
    bool public paused;

    constructor() Ownable(msg.sender) {}

    function setFeeRate(uint256 newRate) external onlyOwner {
        require(newRate <= 1000, "Too high");
        feeRate = newRate;
    }

    function setOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "Zero address");
        oracle = newOracle;
    }

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function withdraw(uint256 amount) external onlyOwner {
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /// User-facing function: no access control needed (uses msg.sender balance)
    function userWithdraw() external {
        // This is user-facing, NOT admin — should not flag
    }
}
