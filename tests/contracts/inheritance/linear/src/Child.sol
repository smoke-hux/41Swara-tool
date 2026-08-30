// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Middle} from "./Middle.sol";

contract Child is Middle {
    function childFn() external onlyBase onlyMiddle {
        _counter = 0;
    }
}
