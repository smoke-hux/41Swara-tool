// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20LiabilitySync {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ERC4626SlashLiabilitySync {
    IERC20LiabilitySync public asset;
    uint256 public totalSupply;
    uint256 public weeklyRevenue;

    constructor(IERC20LiabilitySync asset_) {
        asset = asset_;
    }

    function buyDbr(uint256 amount) external {
        weeklyRevenue += amount;
    }

    function slash(address receiver, uint256 amount) external {
        if (weeklyRevenue >= amount) {
            weeklyRevenue -= amount;
        } else {
            weeklyRevenue = 0;
        }

        require(asset.transfer(receiver, amount), "transfer failed");
    }

    function totalAssets() public view returns (uint256) {
        uint256 assets = asset.balanceOf(address(this));
        if (assets <= weeklyRevenue) {
            return 0;
        }

        return assets - weeklyRevenue;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }

        return assets * totalSupply / totalAssets();
    }
}
