// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: pull-payment withdrawal (no push loop, no DoS surface).
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

/// @notice Auction that credits outbid participants and lets them withdraw
/// themselves. Nothing is pushed in a loop, so a single reverting recipient
/// cannot block anyone else.
contract PullPaymentAuction {
    address public immutable seller;
    uint256 public immutable endTime;

    address public highestBidder;
    uint256 public highestBid;
    bool public settled;

    mapping(address => uint256) public withdrawable;

    event BidPlaced(address indexed bidder, uint256 amount);
    event Withdrawal(address indexed account, uint256 amount);
    event Settled(address indexed winner, uint256 amount);

    constructor(address seller_, uint256 duration) {
        require(seller_ != address(0), "zero seller");
        require(duration > 0, "zero duration");
        seller = seller_;
        endTime = block.timestamp + duration;
    }

    function bid() external payable {
        require(block.timestamp < endTime, "auction ended");
        require(msg.value > highestBid, "bid too low");

        if (highestBidder != address(0)) {
            // Credit, do not push. The previous bidder pulls their refund.
            withdrawable[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit BidPlaced(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = withdrawable[msg.sender];
        require(amount > 0, "nothing to withdraw");

        withdrawable[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function settle() external {
        require(block.timestamp >= endTime, "auction live");
        require(!settled, "already settled");

        settled = true;
        uint256 proceeds = highestBid;
        withdrawable[seller] += proceeds;
        emit Settled(highestBidder, proceeds);
    }
}
