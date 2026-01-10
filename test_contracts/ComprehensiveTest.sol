// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Test contract to verify scanner improvements and reduced false positives
contract ComprehensiveTest {
    using SafeMath for uint256; // Should NOT trigger arithmetic warnings

    address public owner;
    uint256 public constant MAX_SUPPLY = 10000;
    uint256 public immutable deploymentTime; // Should NOT trigger "could be immutable" warnings
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    // ReentrancyGuard should prevent reentrancy warnings
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        deploymentTime = block.timestamp;
    }

    // Should NOT trigger access control warning because it has onlyOwner modifier
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // Should NOT trigger arithmetic warnings because SafeMath is used
    function safeTransfer(address to, uint256 amount) external {
        balances[msg.sender] = balances[msg.sender].sub(amount);
        balances[to] = balances[to].add(amount);
    }

    // Should NOT trigger reentrancy warning because of nonReentrant modifier
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0; // State change before external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // View functions should NOT trigger access control warnings
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }

    // Simple loop counter should NOT trigger arithmetic overflow warnings
    function processArray(uint256[] memory data) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < data.length; i++) { // Loop counter should be OK
            sum += data[i];
        }
        return sum;
    }
}

// CRITICAL VULNERABILITIES - These SHOULD be detected
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;

    // SHOULD DETECT: Missing access control on critical function
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // SHOULD DETECT: Reentrancy vulnerability
    function vulnerableWithdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0; // State change AFTER external call
    }

    // SHOULD DETECT: tx.origin authentication
    function checkOrigin() external view returns (bool) {
        return tx.origin == owner;
    }

    // SHOULD DETECT: Weak randomness
    function badRandom() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
    }

    // SHOULD DETECT: Unchecked low-level call
    function uncheckedCall(address target) external {
        target.call(abi.encodeWithSignature("someFunction()"));
    }

    // SHOULD DETECT: Price oracle manipulation
    function getPrice(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
}

// DeFi Contract - Should detect DeFi-specific issues
contract DeFiContract {
    // SHOULD DETECT: Missing slippage protection
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        // Swap logic without minAmountOut parameter
    }

    // SHOULD DETECT: Flash loan attack surface
    function flashLoan(uint256 amount) external {
        uint256 price = getSpotPrice(); // Using spot price
        // loan logic
    }

    function getSpotPrice() internal view returns (uint256) {
        return address(this).balance;
    }
}

// NFT Contract - Should detect NFT-specific issues
contract NFTContract {
    uint256 public nextTokenId;
    mapping(uint256 => address) public owners;

    // SHOULD DETECT: Unlimited minting (no supply cap)
    function mint() external {
        owners[nextTokenId] = msg.sender;
        nextTokenId++;
    }

    // SHOULD DETECT: Unsafe transfer (not using safeTransferFrom)
    function transfer(address to, uint256 tokenId) external {
        owners[tokenId] = to;
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
    }
}
