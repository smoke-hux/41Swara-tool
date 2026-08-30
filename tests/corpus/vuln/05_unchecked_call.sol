// SPDX-License-Identifier: MIT
// EXPECT: UncheckedReturnValues
// VULN CORPUS CASE — low-level call return values dropped on the floor (SWC-104).
pragma solidity 0.8.24;

interface IToken {
    function transfer(address to, uint256 value) external returns (bool);
}

contract IgnoredReturns {
    mapping(address => uint256) public owed;

    // VULNERABLE: the bool from `send` is discarded, so a failed payout is
    // silently treated as a success and the debt is cleared anyway.
    function payout(address payable to) external {
        uint256 amount = owed[to];
        owed[to] = 0;
        to.send(amount);
    }

    // VULNERABLE: the success flag from `.call` is never inspected.
    function forward(address target, bytes calldata data) external {
        target.call(data);
    }

    // VULNERABLE: a token returning `false` (rather than reverting) is treated
    // as if the transfer had succeeded.
    function sweep(IToken token, address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
