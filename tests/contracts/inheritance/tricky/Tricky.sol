// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// import "./Ghost.sol";
/*
import "./Ghost.sol";
contract Commented is Ghost {
    modifier ghostModifier() { _; }
}
*/

contract Real {
    string public note = "import \"./Ghost.sol\"; contract Commented is Ghost";
    string public island = "is not an inheritance keyword";
}
