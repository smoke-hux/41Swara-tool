// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Base {
    address internal _admin;

    modifier onlyBase() {
        require(msg.sender == _admin, "not admin");
        _;
    }

    function baseFn() public view returns (address) {
        return _admin;
    }
}
