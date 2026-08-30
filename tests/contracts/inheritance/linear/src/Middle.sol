// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Base.sol";

abstract contract Middle is Base {
    uint256 internal _counter;

    modifier onlyMiddle() {
        require(msg.sender == _admin, "not middle");
        _;
    }

    function middleFn() public returns (uint256) {
        _counter += 1;
        return _counter;
    }
}
