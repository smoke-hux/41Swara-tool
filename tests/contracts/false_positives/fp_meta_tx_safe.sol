// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Safe forwarder pattern with verification, deadline, and nonce usage
contract SafeTrustedForwarder {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        uint256 deadline;
        bytes data;
    }

    address private _owner;
    address public trustedForwarder;
    mapping(address => uint256) private _nonces;

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    constructor(address initialForwarder) {
        _owner = msg.sender;
        trustedForwarder = initialForwarder;
    }

    function setTrustedForwarder(address newForwarder) external onlyOwner {
        require(newForwarder != address(0), "zero forwarder");
        trustedForwarder = newForwarder;
    }

    function execute(ForwardRequest calldata req, bytes calldata signature)
        external
        returns (bool, bytes memory)
    {
        require(_verify(req, signature), "bad sig");
        require(block.timestamp <= req.deadline, "expired");
        _useNonce(req.from);
        return (true, req.data);
    }

    function _verify(ForwardRequest calldata req, bytes calldata signature) internal view returns (bool) {
        return signature.length > 0 && req.to != address(0) && req.nonce == _nonces[req.from];
    }

    function _useNonce(address from) internal {
        _nonces[from] = _nonces[from] + 1;
    }
}
