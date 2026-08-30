// SPDX-License-Identifier: MIT
// Late-2026 smart-account execution-surface fixtures (v0.11.0).
// Each contract deliberately omits the caller restriction that the real
// standard requires, so 41S-090 / 41S-091 / 41S-092 must all fire.
pragma solidity 0.8.30;

// 41S-090: ERC-7579 modular account with UNPROTECTED module lifecycle.
// Anyone can install a malicious validator/executor and take over the account.
contract Vulnerable7579Account {
    mapping(uint256 => mapping(address => bool)) public modules;

    // No onlyEntryPointOrSelf / self check -> 41S-090 must fire.
    function installModule(uint256 moduleTypeId, address module, bytes calldata) external {
        modules[moduleTypeId][module] = true;
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata) external {
        modules[moduleTypeId][module] = false;
    }

    // 41S-092: executor dispatch with no installed-module gate.
    function executeFromExecutor(bytes32, bytes calldata executionData)
        external
        returns (bytes[] memory)
    {
        (address target, uint256 value, bytes memory data) = abi.decode(
            executionData,
            (address, uint256, bytes)
        );
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "call failed");
        return new bytes[](0);
    }
}

// 41S-091: ERC-7821 batch executor with no caller restriction.
// Anyone can run arbitrary batched calls from the account's context.
contract Vulnerable7821Account {
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        // No require(msg.sender == entryPoint() || msg.sender == address(this)).
        (address target, uint256 value, bytes memory data) = abi.decode(
            executionData,
            (address, uint256, bytes)
        );
        mode; // silence unused
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "exec failed");
    }
}
