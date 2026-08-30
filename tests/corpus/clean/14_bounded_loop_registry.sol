// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: array handling with explicit length bounds and paginated
// reads — no unbounded loop over caller-controlled input.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

contract MemberRegistry {
    uint256 public constant MAX_BATCH = 50;

    address public immutable admin;
    address[] private _members;
    mapping(address => bool) public isMember;

    event MemberAdded(address indexed account);
    event MemberRemoved(address indexed account);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address admin_) {
        require(admin_ != address(0), "zero admin");
        admin = admin_;
    }

    function memberCount() external view returns (uint256) {
        return _members.length;
    }

    /// @dev The batch size is bounded by a constant, so the loop can never grow
    /// past the block gas limit regardless of what the caller supplies.
    function addMembers(address[] calldata accounts) external onlyAdmin {
        uint256 len = accounts.length;
        require(len > 0, "empty batch");
        require(len <= MAX_BATCH, "batch too large");

        for (uint256 i = 0; i < len; ++i) {
            address account = accounts[i];
            require(account != address(0), "zero member");
            if (!isMember[account]) {
                isMember[account] = true;
                _members.push(account);
                emit MemberAdded(account);
            }
        }
    }

    /// @dev Paginated read: the caller chooses the window, and the window is
    /// clamped to the array length.
    function membersSlice(uint256 offset, uint256 limit)
        external
        view
        returns (address[] memory page)
    {
        uint256 total = _members.length;
        if (offset >= total) {
            return new address[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        page = new address[](end - offset);
        for (uint256 i = offset; i < end; ++i) {
            page[i - offset] = _members[i];
        }
    }
}
