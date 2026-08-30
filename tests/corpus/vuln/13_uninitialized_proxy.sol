// SPDX-License-Identifier: MIT
// EXPECT: DoubleInitialization
// VULN CORPUS CASE — an initializer that anyone can call, and can call twice.
pragma solidity 0.8.24;

contract UpgradeableVaultV1 {
    address public owner;
    address public treasury;
    uint256 public feeBps;
    bool public initializedFlagNeverChecked;

    // VULNERABLE: no `initializer` modifier and no re-entry guard on the
    // initialisation flag — an attacker front-runs deployment (or simply calls
    // it again) and takes ownership of the proxy.
    function initialize(address owner_, address treasury_) public {
        owner = owner_;
        treasury = treasury_;
        feeBps = 30;
    }

    function setTreasury(address treasury_) external {
        require(msg.sender == owner, "not owner");
        treasury = treasury_;
    }

    // VULNERABLE: unrestricted upgrade authorisation hook.
    function _authorizeUpgrade(address) internal {}

    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
        assembly {
            sstore(
                0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc,
                newImplementation
            )
        }
    }
}
