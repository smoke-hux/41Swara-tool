// SPDX-License-Identifier: MIT
// EXPECT: RandomnessVulnerabilities
// VULN CORPUS CASE — on-chain values used as a randomness source (SWC-120).
pragma solidity 0.8.24;

contract Lottery {
    address[] public players;
    uint256 public prize;

    function enter() external payable {
        require(msg.value == 0.1 ether, "wrong entry fee");
        players.push(msg.sender);
        prize += msg.value;
    }

    // VULNERABLE: block.timestamp, block.prevrandao and the player count are all
    // observable or influenceable; a miner or a same-block caller can predict
    // the winner and only enter when they win.
    function pickWinner() external returns (address winner) {
        uint256 seed = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, players.length))
        );
        winner = players[seed % players.length];
        payable(winner).transfer(prize);
        prize = 0;
        delete players;
    }

    // VULNERABLE: blockhash of a recent block is equally predictable.
    function coinFlip() external view returns (bool) {
        return uint256(blockhash(block.number - 1)) % 2 == 0;
    }
}
