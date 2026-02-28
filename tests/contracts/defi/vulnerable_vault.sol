// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit(uint256 amount) external {
        uint256 sharesToMint;
        if (totalShares == 0) {
            sharesToMint = amount; // First depositor sets rate - donation attack vector
        } else {
            sharesToMint = amount * totalShares / address(this).balance;
        }
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }

    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return address(this).balance * 1e18 / totalShares; // balanceOf(this) in share price
    }

    function swap(uint256 amountIn) external returns (uint256) {
        uint256 amountOut = calculateOutput(amountIn);
        // No slippage protection! No minOutput parameter
        return amountOut;
    }

    function calculateOutput(uint256 input) internal pure returns (uint256) {
        return input * 997 / 1000;
    }
}
