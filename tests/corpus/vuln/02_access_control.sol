// SPDX-License-Identifier: MIT
// EXPECT: AccessControl
// VULN CORPUS CASE — privileged functions with no caller check at all.
pragma solidity 0.8.24;

contract UnprotectedAdmin {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: anyone can seize ownership.
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // VULNERABLE: no access control on a value-moving admin function.
    function withdrawAll(address payable to) public {
        to.transfer(address(this).balance);
    }

    // VULNERABLE: unrestricted mint.
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    // VULNERABLE: unrestricted self-destruct-equivalent config change.
    function setFee(uint256 newFeeBps) public {
        feeBps = newFeeBps;
    }

    receive() external payable {}
}
