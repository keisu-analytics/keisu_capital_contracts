// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "openzeppelin-contracts/contracts/proxy/Proxy.sol";
import "openzeppelin-contracts/contracts/utils/StorageSlot.sol";

contract TransparentStaticProxy is Proxy {
    //avoid collisions with implementation storage
    bytes32 internal constant IMPLSLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _impl) payable {
        StorageSlot.getAddressSlot(IMPLSLOT).value = _impl;
    }

    function _implementation() internal view override returns (address) {
        return StorageSlot.getAddressSlot(IMPLSLOT).value;
    }
}
