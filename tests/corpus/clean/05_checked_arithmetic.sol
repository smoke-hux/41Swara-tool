// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: Solidity 0.8 checked arithmetic; no SafeMath needed, and
// the only `unchecked` block is provably safe because of the guard above it.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

contract CheckedAccounting {
    uint256 public constant BPS_DENOMINATOR = 10_000;

    mapping(address => uint256) public shares;
    uint256 public totalShares;

    /// @dev 0.8.x reverts on overflow, so `+=` needs no SafeMath.
    function mintShares(address to, uint256 amount) external {
        require(to != address(0), "zero address");
        shares[to] += amount;
        totalShares += amount;
    }

    /// @dev The `require` proves `shares[msg.sender] >= amount`, so the
    /// subtraction inside `unchecked` cannot underflow. Skipping the redundant
    /// check is a deliberate gas optimisation, not a vulnerability.
    function burnShares(uint256 amount) external {
        uint256 balance = shares[msg.sender];
        require(balance >= amount, "insufficient shares");
        unchecked {
            shares[msg.sender] = balance - amount;
            totalShares -= amount;
        }
    }

    /// @dev Multiply before divide so precision is not lost, and reject a zero
    /// denominator explicitly rather than relying on the panic.
    function proportionalAmount(uint256 amount, uint256 numerator, uint256 denominator)
        external
        pure
        returns (uint256)
    {
        require(denominator != 0, "zero denominator");
        return (amount * numerator) / denominator;
    }

    function feeOf(uint256 amount, uint256 feeBps) external pure returns (uint256) {
        require(feeBps <= BPS_DENOMINATOR, "fee out of range");
        return (amount * feeBps) / BPS_DENOMINATOR;
    }
}
