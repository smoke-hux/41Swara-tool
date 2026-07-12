// SPDX-License-Identifier: MIT
// Safe counterparts to the mid-2026 exploit fixtures. These use the recommended
// mitigations and must NOT trigger 41S-086 or 41S-088.
pragma solidity 0.8.30;

// Safe: ERC-7201 namespaced storage — 41S-086 must NOT fire.
contract Safe7702Delegate {
    /// @custom:storage-location erc7201:myapp.delegate.storage
    struct DelegateStorage {
        address owner;
        uint256 nonce;
    }

    function execute(bytes calldata data) external {
        require(msg.sender == address(this), "only self");
        _run(data);
    }

    function _run(bytes calldata) internal {}
}

// Safe: fill() binds originData to a verified orderId and tracks filled orders.
// 41S-088 must NOT fire.
contract SafeSettler {
    mapping(bytes32 => bool) public filledOrders;

    function fill(bytes32 orderId, bytes calldata originData, bytes calldata) external {
        require(!filledOrders[orderId], "filled");
        require(orderId == keccak256(originData), "bad order");
        filledOrders[orderId] = true;
        (address token, address to, uint256 amount) = abi.decode(
            originData,
            (address, address, uint256)
        );
        IERC20(token).transfer(to, amount);
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}
