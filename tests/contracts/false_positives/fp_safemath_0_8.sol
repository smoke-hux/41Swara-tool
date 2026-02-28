// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Solidity 0.8+ auto-revert arithmetic — should produce 0 arithmetic overflow/underflow warnings
contract SafeMathContract {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // Auto-reverts on overflow in 0.8+
    }

    function sub(uint256 a, uint256 b) public pure returns (uint256) {
        return a - b; // Auto-reverts on underflow in 0.8+
    }

    function mul(uint256 a, uint256 b) public pure returns (uint256) {
        return a * b; // Auto-reverts on overflow in 0.8+
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    function burn(address from, uint256 amount) external {
        require(balances[from] >= amount, "Insufficient");
        totalSupply -= amount;
        balances[from] -= amount;
    }
}
