// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract A {
    function who() public virtual returns (string memory) { return "A"; }
}

contract B is A {
    function who() public virtual override returns (string memory) { return "B"; }
}

contract C is A {
    function who() public virtual override returns (string memory) { return "C"; }
}

contract D is B, C {
    function who() public override(B, C) returns (string memory) { return "D"; }
}
