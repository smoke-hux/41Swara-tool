// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Permit flow with deadline, domain separation, and nonce invalidation
contract SafePermitFlow {
    mapping(address => uint256) public nonces;
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(
            abi.encode(DOMAIN_SEPARATOR, owner, spender, value, nonces[owner], deadline)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "invalid sig");
        require(recovered == owner, "bad sig");
        nonces[owner] = nonces[owner] + 1;
    }
}
