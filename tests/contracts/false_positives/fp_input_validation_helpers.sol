// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Safe input handling patterns that should not trigger validation findings
contract SafeInputValidationHelpers {
    function processPayload(bytes calldata payload) external {
        require(payload.length == 64, "invalid payload");
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");
    }

    function batchUpdate(address[] calldata users, uint256[] calldata amounts) external pure returns (uint256) {
        require(users.length == amounts.length, "length mismatch");
        require(users.length > 0 && users.length <= 100, "invalid length");
        return users.length;
    }

    function _isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
}
