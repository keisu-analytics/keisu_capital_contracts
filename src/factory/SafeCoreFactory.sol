// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "../proxy/TransparentStaticProxy.sol";
import "../core/SafeCore.sol";

contract SafeCoreFactory {
    address public implementation;

    constructor() payable {
        implementation = address(new SafeCore());
    }

    function createSafeCore(address org) public returns (address) {
        SafeCore proxy = SafeCore(address(new TransparentStaticProxy(implementation)));
        proxy.initialize(org);
        return address(proxy);
    }
}
