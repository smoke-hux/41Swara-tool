// SPDX-License-Identifier: MIT
// CLEAN CORPUS CASE
// Pattern under test: SafeERC20-style wrapper around non-conforming tokens.
// Every finding reported on this file is a suspected FALSE POSITIVE.
pragma solidity 0.8.24;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

library Address {
    error AddressEmptyCode(address target);

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.call(data);
        if (!success) {
            _revert(returndata);
        }
        if (returndata.length == 0 && target.code.length == 0) {
            revert AddressEmptyCode(target);
        }
        return returndata;
    }

    function _revert(bytes memory returndata) private pure {
        if (returndata.length > 0) {
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        }
        revert("Address: low-level call failed");
    }
}

/// @notice Wraps ERC-20 calls so that tokens which return nothing (USDT) and
/// tokens which return `false` are both handled correctly.
library SafeERC20 {
    using Address for address;

    error SafeERC20FailedOperation(address token);

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
    }
}

contract TokenEscrow {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    address public immutable beneficiary;

    constructor(IERC20 token_, address beneficiary_) {
        require(address(token_) != address(0), "zero token");
        require(beneficiary_ != address(0), "zero beneficiary");
        token = token_;
        beneficiary = beneficiary_;
    }

    function fund(uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    function release(uint256 amount) external {
        require(msg.sender == beneficiary, "not beneficiary");
        token.safeTransfer(beneficiary, amount);
    }
}
