// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Upgrade/admin functions protected by internal owner checks
contract SafeProxyUpgrade {
    address private _owner;
    address public implementation;

    constructor() {
        _owner = msg.sender;
    }

    function _checkOwner() internal view {
        require(msg.sender == _owner, "not owner");
    }

    function transferOwnership(address newOwner) public {
        _checkOwner();
        require(newOwner != address(0), "zero owner");
        _owner = newOwner;
    }

    function upgradeTo(address newImplementation) public {
        _checkOwner();
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
    }

    function setImplementation(address newImplementation) public {
        _checkOwner();
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
    }
}
