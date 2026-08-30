// SPDX-License-Identifier: MIT
// EXPECT: DelegateCalls
// VULN CORPUS CASE — delegatecall to a caller-supplied address (SWC-112).
pragma solidity 0.8.24;

contract Proxy {
    address public owner;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: the target is fully attacker-controlled and runs in this
    // contract's storage context, so it can overwrite `owner`.
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory out) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return out;
    }

    // VULNERABLE: no access control on the implementation pointer either.
    function setImplementation(address impl) external {
        implementation = impl;
    }

    fallback() external payable {
        address impl = implementation;
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok, "fallback failed");
    }
}
