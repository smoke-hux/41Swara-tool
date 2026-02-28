// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnprotectedAdmin {
    address public treasury;
    uint256 public feeRate;

    function setFeeRate(uint256 _rate) external {
        feeRate = _rate; // No access control!
    }

    function setTreasury(address _treasury) external {
        treasury = _treasury; // No access control!
    }

    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance); // No access control!
    }
}
