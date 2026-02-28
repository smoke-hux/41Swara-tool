// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract ProtectedAdmin is Ownable {
    address public treasury;
    uint256 public feeRate;

    constructor() Ownable(msg.sender) {}

    function setFeeRate(uint256 _rate) external onlyOwner {
        feeRate = _rate;
        emit FeeRateUpdated(_rate);
    }

    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Zero address");
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    event FeeRateUpdated(uint256 rate);
    event TreasuryUpdated(address treasury);
}
