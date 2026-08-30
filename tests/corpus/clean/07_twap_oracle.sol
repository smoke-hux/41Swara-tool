// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: TWAP price consumption with staleness and bound checks.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

interface IChainlinkAggregator {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
    function decimals() external view returns (uint8);
}

interface ITwapOracle {
    /// @notice Time-weighted average price over `period` seconds.
    function consult(address token, uint32 period) external view returns (uint256);
}

/// @notice Prices are never read from a spot reserve ratio. A Chainlink feed is
/// validated for staleness, round completeness and sign, then cross-checked
/// against an independent TWAP with a hard deviation bound.
contract PriceConsumer {
    uint256 public constant MAX_DEVIATION_BPS = 200; // 2%
    uint256 public constant BPS = 10_000;
    uint32 public constant TWAP_PERIOD = 1800; // 30 minutes

    IChainlinkAggregator public immutable feed;
    ITwapOracle public immutable twap;
    address public immutable token;
    uint256 public immutable maxStaleness;

    error StalePrice(uint256 updatedAt);
    error InvalidPrice(int256 answer);
    error IncompleteRound(uint80 roundId, uint80 answeredInRound);
    error DeviationTooLarge(uint256 chainlinkPrice, uint256 twapPrice);

    constructor(
        IChainlinkAggregator feed_,
        ITwapOracle twap_,
        address token_,
        uint256 maxStaleness_
    ) {
        require(address(feed_) != address(0), "zero feed");
        require(address(twap_) != address(0), "zero twap");
        require(token_ != address(0), "zero token");
        require(maxStaleness_ > 0, "zero staleness");
        feed = feed_;
        twap = twap_;
        token = token_;
        maxStaleness = maxStaleness_;
    }

    function getPrice() external view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) =
            feed.latestRoundData();

        if (answer <= 0) revert InvalidPrice(answer);
        if (answeredInRound < roundId) revert IncompleteRound(roundId, answeredInRound);
        if (block.timestamp - updatedAt > maxStaleness) revert StalePrice(updatedAt);

        uint256 chainlinkPrice = uint256(answer);
        uint256 twapPrice = twap.consult(token, TWAP_PERIOD);

        uint256 diff = chainlinkPrice > twapPrice
            ? chainlinkPrice - twapPrice
            : twapPrice - chainlinkPrice;

        if ((diff * BPS) / twapPrice > MAX_DEVIATION_BPS) {
            revert DeviationTooLarge(chainlinkPrice, twapPrice);
        }

        return chainlinkPrice;
    }
}
