// SPDX-License-Identifier: MIT
// EXPECT: SignatureVulnerabilities
// VULN CORPUS CASE — `abi.encodePacked` over adjacent dynamic types produces
// hash collisions, and the signature check has no nonce, so it replays.
pragma solidity 0.8.24;

contract PackedSignatureAuth {
    address public signer;
    mapping(address => uint256) public credits;

    constructor(address signer_) {
        signer = signer_;
    }

    // VULNERABLE: encodePacked over two dynamic arrays — ("a","bc") and
    // ("ab","c") hash identically, so one signature authorises both.
    function hashRequest(string memory action, string memory target, uint256 amount)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(action, target, amount));
    }

    // VULNERABLE: no nonce, no deadline, no chain id, no domain separator, so
    // a valid signature can be replayed forever and across chains.
    function redeem(
        string calldata action,
        string calldata target,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = hashRequest(action, target, amount);
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        credits[msg.sender] += amount;
    }
}
