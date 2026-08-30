// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: timelocked governance execution. `block.timestamp` is
// used as a coarse deadline with a multi-day delay, where miner drift of a few
// seconds is irrelevant — this is the documented safe use of a timestamp.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

contract Timelock {
    uint256 public constant MINIMUM_DELAY = 2 days;
    uint256 public constant MAXIMUM_DELAY = 30 days;
    uint256 public constant GRACE_PERIOD = 14 days;

    address public immutable admin;
    uint256 public delay;

    mapping(bytes32 => uint256) public queuedAt;

    event Queued(bytes32 indexed id, address target, uint256 value, bytes data, uint256 eta);
    event Executed(bytes32 indexed id, address target, uint256 value, bytes data);
    event Cancelled(bytes32 indexed id);

    error NotAdmin();
    error NotQueued(bytes32 id);
    error TooEarly(uint256 eta);
    error Stale(uint256 eta);
    error CallReverted();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(address admin_, uint256 delay_) {
        require(admin_ != address(0), "zero admin");
        require(delay_ >= MINIMUM_DELAY && delay_ <= MAXIMUM_DELAY, "delay out of range");
        admin = admin_;
        delay = delay_;
    }

    function operationId(address target, uint256 value, bytes calldata data)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(target, value, data));
    }

    function queue(address target, uint256 value, bytes calldata data)
        external
        onlyAdmin
        returns (bytes32 id)
    {
        require(target != address(0), "zero target");
        id = operationId(target, value, data);
        require(queuedAt[id] == 0, "already queued");

        uint256 eta = block.timestamp + delay;
        queuedAt[id] = eta;
        emit Queued(id, target, value, data, eta);
    }

    function cancel(address target, uint256 value, bytes calldata data) external onlyAdmin {
        bytes32 id = operationId(target, value, data);
        if (queuedAt[id] == 0) revert NotQueued(id);
        delete queuedAt[id];
        emit Cancelled(id);
    }

    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyAdmin
        returns (bytes memory)
    {
        bytes32 id = operationId(target, value, data);
        uint256 eta = queuedAt[id];
        if (eta == 0) revert NotQueued(id);
        if (block.timestamp < eta) revert TooEarly(eta);
        if (block.timestamp > eta + GRACE_PERIOD) revert Stale(eta);

        // Clear before the interaction.
        delete queuedAt[id];
        emit Executed(id, target, value, data);

        (bool ok, bytes memory returndata) = target.call{value: value}(data);
        if (!ok) revert CallReverted();
        return returndata;
    }

    receive() external payable {}
}
