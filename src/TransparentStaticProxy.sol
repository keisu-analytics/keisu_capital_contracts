// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;
import "openzeppelin-contracts/contracts/proxy/Proxy.sol";

contract TransparentStaticProxy is Proxy {
    address public impl;

    constructor(address _impl) payable {
        impl = _impl;
    }

    function _implementation() internal view override returns (address) {
        return impl;
    }
}
