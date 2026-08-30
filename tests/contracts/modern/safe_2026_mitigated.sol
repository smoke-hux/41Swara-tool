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

// Safe: ERC-7579 account gating module lifecycle + executor dispatch.
// 41S-090 and 41S-092 must NOT fire.
contract SafeModularAccount {
    mapping(uint256 => mapping(address => bool)) public modules;

    modifier onlyEntryPointOrSelf() {
        require(msg.sender == address(this), "not authorized");
        _;
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata)
        external
        onlyEntryPointOrSelf
    {
        modules[moduleTypeId][module] = true;
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata)
        external
        onlyEntryPointOrSelf
    {
        modules[moduleTypeId][module] = false;
    }

    function executeFromExecutor(bytes32, bytes calldata) external returns (bytes[] memory) {
        require(isModuleInstalled(2, msg.sender), "not an executor");
        return new bytes[](0);
    }

    function isModuleInstalled(uint256 t, address m) public view returns (bool) {
        return modules[t][m];
    }
}

// Safe: ERC-7821 executor restricted to the EntryPoint or the account itself.
// 41S-091 must NOT fire.
contract SafeBatchExecutor {
    address public entryPoint;

    function execute(bytes32, bytes calldata) external payable {
        require(
            msg.sender == entryPoint || msg.sender == address(this),
            "only entryPoint or self"
        );
    }
}
