// SPDX-License-Identifier: MIT
// EXPECT: TxOriginAuth
// VULN CORPUS CASE — tx.origin used for authorisation (SWC-115). A phishing
// contract that the owner is tricked into calling passes this check.
pragma solidity 0.8.24;

contract TxOriginAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        // VULNERABLE: tx.origin is the EOA at the start of the call chain, not
        // the immediate caller.
        require(tx.origin == owner, "not owner");
        _;
    }

    function transferFunds(address payable to, uint256 amount) external onlyOwner {
        to.transfer(amount);
    }

    function changeOwner(address newOwner) external {
        // VULNERABLE: same flaw, inlined.
        require(tx.origin == owner, "not owner");
        owner = newOwner;
    }

    receive() external payable {}
}
