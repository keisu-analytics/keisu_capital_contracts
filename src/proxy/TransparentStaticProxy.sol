// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;
import "openzeppelin-contracts/contracts/proxy/Proxy.sol";
import "openzeppelin-contracts/contracts/utils/StorageSlot.sol";

contract TransparentStaticProxy is Proxy {
    bytes32 internal constant implSlot =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _impl) payable {
        StorageSlot.getAddressSlot(implSlot).value = _impl;
    }

    function _implementation() internal view override returns (address) {
        StorageSlot.getAddressSlot(implSlot).value;
    }
}
