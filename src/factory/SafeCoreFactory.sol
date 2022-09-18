// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "../proxy/TransparentStaticProxy.sol";
import "../core/SafeCore.sol";

contract SafeCoreFactory {
    address public implementation;

    event SafeCoreCreated(address indexed safeCore);

    constructor() payable {
        implementation = address(new SafeCore());
    }

    function createSafeCore(address org) public returns (address) {
        SafeCore proxy = SafeCore(address(new TransparentStaticProxy(implementation)));
        proxy.initialize(org);
        emit SafeCoreCreated(address(proxy));
        return address(proxy);
    }
}
