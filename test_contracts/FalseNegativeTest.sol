// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Test contract for false negative detection
contract FalseNegativeTest {

    mapping(address => uint256) public balances;

    // FN-1: msg.value reused in loop (CRITICAL)
    function batchSend(address[] calldata recipients) external payable {
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: msg.value}("");
            require(ok);
        }
    }

    // FN-2: isContract bypass during construction
    function onlyEOA(address user) external view returns (bool) {
        return isContract(user) == false;
    }

    function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    // FN-3: Return bomb - unbounded return data capture
    function callExternal(address target) external {
        (bool success, bytes memory data) = target.call(abi.encodeWithSignature("getData()"));
        require(success);
        // data could be enormous, consuming all gas
    }

    // FN-4: Unchecked ERC20 transfer (2 args)
    function sendTokens(address token, address to, uint256 amount) external {
        IERC20(token).transfer(to, amount);
    }

    // FN-7: ecrecover without s-value check (malleability)
    function recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        return signer;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
