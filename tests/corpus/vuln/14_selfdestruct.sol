// SPDX-License-Identifier: MIT
// EXPECT: AccessControl
// VULN CORPUS CASE — unprotected selfdestruct plus an unprotected arbitrary
// external call (the Parity wallet failure mode).
pragma solidity 0.8.24;

contract SuicidalWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: anyone can destroy the contract and take its balance.
    function kill(address payable to) public {
        selfdestruct(to);
    }

    // VULNERABLE: arbitrary call with attacker-chosen target, calldata and
    // value — this contract will sign anything on the attacker's behalf.
    function execute(address target, uint256 value, bytes calldata data) public {
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "call failed");
    }

    receive() external payable {}
}
