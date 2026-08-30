// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: ReentrancyGuard + checks-effects-interactions ordering.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

abstract contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        _status = NOT_ENTERED;
    }
}

/// @notice Deposit/withdraw vault. State is zeroed BEFORE the external call
/// (checks-effects-interactions) and the whole path is additionally wrapped in
/// a reentrancy guard, so a re-entering callee sees a zero balance.
contract GuardedVault is ReentrancyGuard {
    mapping(address => uint256) private _balances;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        _balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        uint256 balance = _balances[msg.sender];
        require(amount > 0, "zero withdrawal");
        require(balance >= amount, "insufficient balance");

        // EFFECTS: state is updated before any interaction.
        _balances[msg.sender] = balance - amount;
        emit Withdrawn(msg.sender, amount);

        // INTERACTION: last, and its return value is checked.
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
