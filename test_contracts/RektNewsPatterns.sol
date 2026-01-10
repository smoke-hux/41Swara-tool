// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================================
// REKT.NEWS REAL-WORLD EXPLOIT PATTERNS TEST CONTRACT
// Based on $3.1B+ in actual DeFi losses (2024-2025)
// ============================================================================

// ===========================================================================
// 1. AEVO/RIBBON FINANCE PATTERN ($2.7M - December 2025)
// Vulnerability: Unprotected proxy admin functions + Oracle manipulation
// ===========================================================================
contract AevoPatternVulnerable {
    address public implementation;
    address public oracle;

    // SHOULD DETECT: Unprotected transferOwnership in proxy
    // Exact Aevo exploit pattern - missing access control
    function transferOwnership(address newOwner) external {
        // Missing: onlyOwner modifier
        implementation = newOwner;
    }

    // SHOULD DETECT: Unprotected setImplementation
    // Allowed attacker to hijack oracle in Aevo
    function setImplementation(address newImpl) external {
        // Missing: access control
        implementation = newImpl;
    }

    // SHOULD DETECT: Unprotected oracle configuration
    // Aevo attacker modified oracle to manipulate prices
    function setOracle(address newOracle) external {
        // Missing: governance/timelock
        oracle = newOracle;
    }

    // SHOULD DETECT: Decimal precision mismatch
    // Aevo mixed 1e18 and 1e8 decimals
    function mixedPrecisionCalc(uint256 amount) external pure returns (uint256) {
        uint256 value18 = amount * 1e18;  // 18 decimals
        uint256 value8 = amount * 1e8;    // 8 decimals
        return value18 + value8; // DANGEROUS: mixing precisions
    }
}

// ===========================================================================
// 2. OMNI NFT PATTERN ($1.43M - 2024)
// Vulnerability: Callback reentrancy via onERC721Received
// ===========================================================================
interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

contract OmniPatternVulnerable {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public collateral;

    // SHOULD DETECT: Critical callback reentrancy
    // State changes AFTER safeTransferFrom - exact Omni exploit
    function borrowWithCollateral(address nft, uint256 tokenId, uint256 amount) external {
        // Missing: ReentrancyGuard

        // Transfer NFT as collateral (triggers onERC721Received callback)
        IERC721(nft).safeTransferFrom(msg.sender, address(this), tokenId);

        // VULNERABLE: State changes AFTER callback-triggering operation
        collateral[msg.sender] += 1;
        balances[msg.sender] += amount;

        // Attacker can reenter via onERC721Received before these updates
    }

    // SHOULD DETECT: ERC721 callback without reentrancy protection
    function mintWithNFT(address nft, uint256 tokenId) external {
        IERC721(nft).safeTransferFrom(msg.sender, address(this), tokenId);
        balances[msg.sender] = 1000 ether; // State change after callback
    }
}

// ===========================================================================
// 3. INPUT VALIDATION FAILURES (34.6% of exploits - $69M in 2024)
// Most common vulnerability 2021, 2022, 2024
// ===========================================================================
contract InputValidationVulnerable {
    mapping(address => uint256) public balances;

    // SHOULD DETECT: Unchecked calldata - most dangerous
    // Enables malicious payload injection
    function executeWithCalldata(bytes calldata data) external {
        // Missing: calldata validation
        // Missing: function selector whitelist
        (bool success, ) = address(this).call(data);
        require(success, "Call failed");
    }

    // SHOULD DETECT: Missing array length validation
    // #1 input validation failure pattern
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        // Missing: require(recipients.length == amounts.length)
        // Missing: require(recipients.length > 0 && recipients.length <= MAX)
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
        }
    }

    // SHOULD DETECT: Missing address zero validation
    function setAdmin(address newAdmin) external {
        // Missing: require(newAdmin != address(0))
        // Top vulnerability in access control
    }
}

// ===========================================================================
// 4. SIGNATURE REPLAY ATTACKS (Multiple cross-chain incidents 2024-2025)
// ===========================================================================
contract SignatureReplayVulnerable {
    mapping(address => uint256) public balances;
    // Missing: mapping(address => uint256) public nonces;

    // SHOULD DETECT: Missing nonce in signature verification
    function withdrawWithSignature(
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
        // Missing: nonce in message hash
        // Missing: chainId in message hash

        address signer = recoverSigner(messageHash, signature);
        require(signer == msg.sender, "Invalid signature");

        // Signature can be replayed indefinitely!
        balances[msg.sender] -= amount;
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    // SHOULD DETECT: Cross-chain replay - missing chainId
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) external {
        // Missing: block.chainid in domain separator
        // Can be replayed across different chains
        bytes32 digest = keccak256(abi.encodePacked(owner, spender, value, deadline));
        // Missing: chain ID
    }
}

// ===========================================================================
// 5. MEV EXPLOITATION PATTERNS ($675M MEV profits in 2025)
// 19% year-over-year increase
// ===========================================================================
interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract MEVVulnerable {
    IUniswapV2Router public router;

    // SHOULD DETECT: Missing deadline protection
    // Vulnerable to MEV sandwich attacks
    function swap(
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path
    ) external {
        // Missing: deadline parameter
        // Transaction can be delayed and sandwiched
        router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            msg.sender,
            type(uint256).max // VULNERABLE: no deadline!
        );
    }

    // SHOULD DETECT: Public liquidation - MEV target
    function liquidate(address user) external {
        // Public liquidation = front-running target
        // Bots will front-run profitable liquidations
        // Missing: MEV protection (Flashbots, private relay, commit-reveal)
    }

    // SHOULD DETECT: Oracle price without staleness check
    interface IChainlinkOracle {
        function latestRoundData() external view returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
    }

    function getPriceAndLiquidate(IChainlinkOracle oracle, address user) external {
        (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
        // Missing: require(block.timestamp - updatedAt < THRESHOLD)
        // Stale price enables front-running
    }
}

// ===========================================================================
// 6. ARBITRARY EXTERNAL CALLS ($21M across 18 incidents in 2024)
// ===========================================================================
contract ArbitraryCallVulnerable {
    // SHOULD DETECT: User-controlled call target
    function executeArbitraryCall(address target, bytes calldata data) external {
        // CRITICAL: No address whitelist
        // Attacker can call any contract
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }

    // SHOULD DETECT: Arbitrary delegatecall
    function executeDelegateCall(address implementation, bytes calldata data) external {
        // CRITICAL: Allows arbitrary code execution in contract context
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}

// ===========================================================================
// 7. ACCESS CONTROL - CALLBACK FUNCTIONS (17 incidents 2024)
// ===========================================================================
contract CallbackAccessControlVulnerable {
    mapping(address => uint256) public balances;

    // SHOULD DETECT: Unprotected callback handling funds
    function onERC721Received(
        address,
        address from,
        uint256,
        bytes memory
    ) external returns (bytes4) {
        // Missing: require(approvedContracts[msg.sender])
        // Anyone can trigger this callback
        balances[from] += 1000 ether;
        return this.onERC721Received.selector;
    }

    // SHOULD DETECT: Unrestricted flash loan callback
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // Missing: require(msg.sender == TRUSTED_POOL)
        // Any contract can trigger this
        balances[initiator] += amount;
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// ===========================================================================
// 8. PRECISION LOSS IN CRITICAL CALCULATIONS
// ===========================================================================
contract PrecisionLossVulnerable {
    uint256 public totalSupply = 1000000;

    // SHOULD DETECT: Division before multiplication in pricing
    function calculatePrice(uint256 amount, uint256 multiplier) external view returns (uint256) {
        // WRONG: Division before multiplication loses precision
        return (amount / totalSupply) * multiplier;
        // CORRECT: return (amount * multiplier) / totalSupply;
    }

    // SHOULD DETECT: Integer division in distribution
    function distributeRewards(uint256 totalReward, uint256 totalParticipants) external pure returns (uint256) {
        uint256 rewardPerUser = totalReward / totalParticipants;
        // Missing: remainder handling
        // uint256 remainder = totalReward % totalParticipants;
        return rewardPerUser;
    }
}

// ===========================================================================
// 9. SAFE PATTERN (Should NOT trigger warnings)
// ===========================================================================
contract SafePatternGood {
    bool private locked;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;

    modifier nonReentrant() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SAFE: Has ReentrancyGuard
    function safeWithdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // SAFE: Proper signature verification with nonce and chainId
    function safeWithdrawWithSignature(
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external {
        require(block.timestamp <= deadline, "Expired");

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Withdraw(address user,uint256 amount,uint256 nonce,uint256 deadline)"),
            msg.sender,
            amount,
            nonces[msg.sender]++,  // Nonce prevents replay
            deadline
        ));

        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MyContract"),
            block.chainid,  // ChainID prevents cross-chain replay
            address(this)
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        // Proper signature verification
    }

    // SAFE: Protected proxy upgrade
    function upgradeImplementation(address newImpl) external onlyOwner {
        // Has access control
        require(newImpl != address(0), "Zero address");
        // Safe upgrade
    }
}
