pragma solidity 0.4.24;

contract LegacyContract {
    address owner;
    
    // Legacy constructor syntax (pre-0.5.0)
    function LegacyContract() public {
        owner = msg.sender;
    }
    
    function kill() public {
        // suicide() function deprecated in 0.5.0
        suicide(owner);
    }
    
    function unsafeTransfer(address to) public {
        // tx.origin vulnerability
        require(tx.origin == owner);
        to.transfer(1 ether);
    }
}