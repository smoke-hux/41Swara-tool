// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TestAdvanced {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Bad PRNG - vulnerable
    function randomNumber() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }

    // Reentrancy vulnerability - state change after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // State change after external call!
    }

    // Missing access control on critical function
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        totalSupply += amount;
    }

    // Unchecked low-level call
    function dangerousCall(address target, bytes calldata data) public {
        target.call(data); // Return value not checked!
    }

    // High complexity function
    function complexFunction(uint256 x) public pure returns (uint256) {
        if (x > 100) {
            if (x > 200) {
                if (x > 300) {
                    if (x > 400) {
                        return x * 4;
                    }
                    return x * 3;
                }
                return x * 2;
            }
            return x;
        }
        return 0;
    }

    // Flash loan vulnerability - using spot price
    function getPrice() public view returns (uint256) {
        return balances[address(this)]; // Manipulable by flash loans
    }

    // Missing event emission
    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // No event emitted!
    }

    // Uninitialized state variable
    address admin;

    // String that could be bytes32
    string public shortName = "TEST";

    // Storage read in loop - gas inefficient
    function sumBalances(address[] calldata users) public view returns (uint256) {
        uint256 sum = 0;
        for (uint i = 0; i < users.length; i++) {
            sum += balances[users[i]]; // Storage read in loop
        }
        return sum;
    }

    // Strict equality on balance
    function checkExactBalance() public view returns (bool) {
        return address(this).balance == 100 ether; // Can be manipulated
    }

    // Deprecated function usage
    function oldHash(bytes memory data) public pure returns (bytes32) {
        return sha3(data); // Deprecated - should use keccak256
    }

    // Missing zero address validation
    function setOwner(address newOwner) public {
        owner = newOwner; // No zero address check!
    }

    // Hash collision risk with encodePacked
    function hashData(string memory a, string memory b) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b)); // Collision risk
    }

    // Assembly usage
    function dangerousAssembly(address target) public {
        assembly {
            let result := call(gas(), target, 0, 0, 0, 0, 0)
        }
    }
}