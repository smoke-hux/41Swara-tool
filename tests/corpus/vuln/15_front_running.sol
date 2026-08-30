// SPDX-License-Identifier: MIT
// EXPECT: FrontRunning
// VULN CORPUS CASE — a public swap with no slippage bound and no deadline,
// plus a commit-free reveal that is trivially front-run (SWC-114).
pragma solidity 0.8.24;

contract NaiveSwapper {
    mapping(address => uint256) public reserveIn;
    mapping(address => uint256) public reserveOut;
    mapping(bytes32 => address) public solutions;

    // VULNERABLE: no minimum output and no deadline parameter, so a sandwich
    // bot can move the price around this trade and extract the difference.
    function swapExactIn(address tokenIn, address tokenOut, uint256 amountIn)
        external
        returns (uint256 amountOut)
    {
        uint256 rIn = reserveIn[tokenIn];
        uint256 rOut = reserveOut[tokenOut];
        amountOut = (amountIn * rOut) / (rIn + amountIn);
        reserveIn[tokenIn] = rIn + amountIn;
        reserveOut[tokenOut] = rOut - amountOut;
    }

    // VULNERABLE: the answer is submitted in the clear; anyone watching the
    // mempool copies it with a higher gas price and claims the reward first.
    function submitSolution(string calldata answer) external {
        bytes32 key = keccak256(abi.encodePacked(answer));
        require(solutions[key] == address(0), "already solved");
        solutions[key] = msg.sender;
        payable(msg.sender).transfer(1 ether);
    }

    receive() external payable {}
}
