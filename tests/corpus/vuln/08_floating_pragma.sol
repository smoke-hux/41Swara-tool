// SPDX-License-Identifier: MIT
// EXPECT: PragmaIssues
// VULN CORPUS CASE — floating caret pragma (SWC-103). `^0.8.0` accepts every
// 0.8.x release, so the deployed bytecode is not reproducible and may be built
// with a compiler the code was never tested against.
pragma solidity ^0.8.0;

contract FloatingPragma {
    uint256 public value;

    function setValue(uint256 newValue) public {
        value = newValue;
    }

    function getValue() public view returns (uint256) {
        return value;
    }
}
