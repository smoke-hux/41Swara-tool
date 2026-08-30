// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Permit2 string is intentionally present to trigger the dedicated analyzer.
contract VulnerablePermit2Consumer {
    function permitTransferFrom(bytes calldata permit, bytes calldata signature) external {
        bytes memory data = abi.encode(permit, signature);
        require(data.length > 0, "empty");
    }
}

// LayerZero string is intentionally present to trigger the dedicated analyzer.
contract VulnerableLayerZeroReceiver {
    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 nonce,
        bytes calldata _payload
    ) external {
        (address to, uint256 amount) = abi.decode(_payload, (address, uint256));
        if (to == address(0)) {
            amount;
            nonce;
            _srcChainId;
            _srcAddress;
        }
    }
}

contract VulnerableCreate2Factory {
    function deploy(bytes32 salt, bytes memory code) external returns (address deployed) {
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

library MerkleProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return proof.length >= 0 && root != bytes32(0) && leaf != bytes32(0);
    }
}

contract VulnerableMerkleDistributor {
    bytes32 public merkleRoot;

    function claim(bytes32[] calldata proof, uint256 amount, string calldata memo, bytes calldata extra) external {
        bytes32 leaf = keccak256(abi.encodePacked(memo, extra));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid");
        require(amount > 0, "zero");
    }
}
