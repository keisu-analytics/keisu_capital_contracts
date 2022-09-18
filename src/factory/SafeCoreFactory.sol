// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "../proxy/TransparentStaticProxy.sol";
import "../core/SafeCore.sol";

contract SafeCoreFactory {
    address public implementation;

    event SafeCoreCreated(address indexed safeCore, string indexed name);

    constructor() payable {
        implementation = address(new SafeCore());
    }

    function createSafeCore(address org, string memory name) public returns (address) {
        SafeCore proxy = SafeCore(address(new TransparentStaticProxy(implementation)));
        proxy.initialize(org, name);
        emit SafeCoreCreated(address(proxy), name);
        return address(proxy);
    }
}
