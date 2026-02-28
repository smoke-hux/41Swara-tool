// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title View/pure functions — should not produce state-changing vulnerability warnings
contract ViewPureContract {
    uint256 public value;
    mapping(address => uint256) public balances;

    function getValue() public view returns (uint256) {
        return value;
    }

    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }

    function computeHash(bytes memory data) public pure returns (bytes32) {
        return keccak256(data);
    }

    function addNumbers(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}
