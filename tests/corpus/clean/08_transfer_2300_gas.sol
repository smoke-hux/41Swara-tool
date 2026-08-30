// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: `.transfer` / `.send` forward only 2300 gas, which is not
// enough for a reentrant call frame. These are documented as safe by design.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

contract GasCappedPayouts {
    mapping(address => uint256) public credit;

    event Credited(address indexed account, uint256 amount);
    event Paid(address indexed account, uint256 amount);
    event PayFailed(address indexed account, uint256 amount);

    function fund(address account) external payable {
        require(account != address(0), "zero account");
        credit[account] += msg.value;
        emit Credited(account, msg.value);
    }

    /// @dev `.transfer` reverts on failure and caps gas at 2300.
    function claim() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "nothing to claim");
        credit[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
        emit Paid(msg.sender, amount);
    }

    /// @dev `.send` returns a bool instead of reverting; the result is checked
    /// and the credit is restored on failure rather than silently dropped.
    function claimNonReverting() external {
        uint256 amount = credit[msg.sender];
        require(amount > 0, "nothing to claim");
        credit[msg.sender] = 0;

        bool sent = payable(msg.sender).send(amount);
        if (!sent) {
            credit[msg.sender] = amount;
            emit PayFailed(msg.sender, amount);
            return;
        }
        emit Paid(msg.sender, amount);
    }
}
