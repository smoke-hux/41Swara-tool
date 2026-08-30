// SPDX-License-Identifier: MIT
// EXPECT: TimeManipulation
// VULN CORPUS CASE — `block.timestamp` drives fine-grained settlement, where a
// few seconds of validator drift changes the outcome (SWC-116).
pragma solidity 0.8.24;

contract TimeGatedJackpot {
    uint256 public jackpot;
    uint256 public lastPlay;
    uint256 public settlementTime;

    function play() external payable {
        require(msg.value >= 1 ether, "stake too low");
        jackpot += msg.value;

        // VULNERABLE: a one-second window chosen by the block producer.
        if (block.timestamp % 15 == 0) {
            payable(msg.sender).transfer(jackpot);
            jackpot = 0;
        }

        lastPlay = block.timestamp;
    }

    // VULNERABLE: the sole settlement gate is a direct timestamp comparison
    // with a window short enough for a validator to influence.
    function settle() external {
        require(block.timestamp >= settlementTime, "not yet");
        require(block.timestamp <= settlementTime + 2, "window closed");
        payable(msg.sender).transfer(jackpot);
        jackpot = 0;
    }

    function claimWindow() external view returns (bool) {
        return block.timestamp < lastPlay + 3;
    }
}
