// SPDX-License-Identifier: MIT
// EXPECT: DoSAttacks
// VULN CORPUS CASE — unbounded loop over an attacker-growable array, combined
// with a push-payment loop that one reverting recipient can wedge (SWC-113/128).
pragma solidity 0.8.24;

contract PushPayoutDistributor {
    address[] public recipients;
    mapping(address => uint256) public owed;

    // VULNERABLE: anyone can grow the array without bound.
    function register() external {
        recipients.push(msg.sender);
    }

    // VULNERABLE: iterates the whole unbounded array; eventually exceeds the
    // block gas limit and the function is permanently bricked.
    function distribute() external payable {
        uint256 share = msg.value / recipients.length;
        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABLE: a single recipient whose fallback reverts blocks the
            // payout for every other recipient.
            payable(recipients[i]).transfer(share);
        }
    }

    function sumAll() external view returns (uint256 total) {
        for (uint256 i = 0; i < recipients.length; i++) {
            total += owed[recipients[i]];
        }
    }
}
