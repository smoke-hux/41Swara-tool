// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract BaseS {
    modifier guard() virtual {
        require(msg.sender != address(0), "base");
        _;
    }

    function value() internal virtual returns (uint256) {
        return 1;
    }
}

contract Derived is BaseS {
    modifier guard() override {
        require(msg.sender == address(this), "derived");
        _;
    }

    function value() public override returns (uint256) {
        return 2;
    }
}
