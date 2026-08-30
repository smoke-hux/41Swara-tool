// SPDX-License-Identifier: MIT
// EXPECT: OracleManipulation
// VULN CORPUS CASE — collateral valued from a spot AMM reserve ratio, which a
// flash loan can move within a single transaction.
pragma solidity 0.8.24;

interface IUniswapV2Pair {
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function token0() external view returns (address);
}

contract SpotPriceLending {
    IUniswapV2Pair public immutable pair;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(IUniswapV2Pair pair_) {
        pair = pair_;
    }

    // VULNERABLE: the instantaneous reserve ratio IS the price. No TWAP, no
    // Chainlink cross-check, no staleness bound.
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    // VULNERABLE: borrowing power is derived from the manipulable spot price.
    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;
        require(debt[msg.sender] + amount <= collateralValue / 2, "undercollateralised");
        debt[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
}
