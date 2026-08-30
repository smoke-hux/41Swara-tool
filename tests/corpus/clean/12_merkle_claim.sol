// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: Merkle-proof airdrop claim. The leaf is built with
// `abi.encode` (not `encodePacked`) and double-hashed, so no collision or
// second-preimage trick applies; claims are marked before payout.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool)
    {
        return processProof(proof, leaf) == root;
    }

    function processProof(bytes32[] memory proof, bytes32 leaf)
        internal
        pure
        returns (bytes32 computedHash)
    {
        computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}

interface IMintableToken {
    function mint(address to, uint256 amount) external;
}

contract MerkleAirdrop {
    bytes32 public immutable merkleRoot;
    IMintableToken public immutable token;

    mapping(address => bool) public claimed;

    event Claimed(address indexed account, uint256 amount);

    error AlreadyClaimed(address account);
    error InvalidProof();

    constructor(bytes32 merkleRoot_, IMintableToken token_) {
        require(merkleRoot_ != bytes32(0), "zero root");
        require(address(token_) != address(0), "zero token");
        merkleRoot = merkleRoot_;
        token = token_;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        if (claimed[msg.sender]) revert AlreadyClaimed(msg.sender);

        // Double hashing the leaf prevents a proof node from being passed off
        // as a leaf.
        bytes32 leaf = keccak256(abi.encode(keccak256(abi.encode(msg.sender, amount))));
        if (!MerkleProof.verify(proof, merkleRoot, leaf)) revert InvalidProof();

        claimed[msg.sender] = true;
        emit Claimed(msg.sender, amount);

        token.mint(msg.sender, amount);
    }
}
