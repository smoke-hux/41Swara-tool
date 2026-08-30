// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: pure math library plus view-only accessors. No state is
// written, no external call is made, nothing here is attacker-reachable.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

library Math {
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a & b) + ((a ^ b) >> 1);
    }

    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "division by zero");
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    function sqrt(uint256 a) internal pure returns (uint256 result) {
        if (a == 0) {
            return 0;
        }
        result = 1;
        uint256 x = a;
        if (x >> 128 > 0) {
            x >>= 128;
            result <<= 64;
        }
        if (x >> 64 > 0) {
            x >>= 64;
            result <<= 32;
        }
        if (x >> 32 > 0) {
            x >>= 32;
            result <<= 16;
        }
        result = (result + a / result) >> 1;
        result = (result + a / result) >> 1;
        result = Math.min(result, a / result);
    }
}

contract Statistics {
    using Math for uint256;

    uint256[] private _samples;

    function record(uint256 sample) external {
        _samples.push(sample);
    }

    function count() external view returns (uint256) {
        return _samples.length;
    }

    function sampleAt(uint256 index) external view returns (uint256) {
        require(index < _samples.length, "index out of range");
        return _samples[index];
    }

    function rootOf(uint256 value) external pure returns (uint256) {
        return value.sqrt();
    }

    function ceilingDivide(uint256 a, uint256 b) external pure returns (uint256) {
        return a.ceilDiv(b);
    }
}
