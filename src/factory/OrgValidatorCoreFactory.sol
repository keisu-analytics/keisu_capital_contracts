// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "../proxy/TransparentStaticProxy.sol";
import "../core/OrgValidatorCore.sol";

contract OrgValidatorCoreFactory {
    address public implementation;

    event OrgValidatorCoreCreated(address indexed orgValidatorCore, string indexed name, OrgValidatorCore.Membership[] _roleMemberships, OrgValidatorCore.Permission[] _orgPermissions);

    constructor() payable {
        implementation = address(new OrgValidatorCore());
    }

    function createOrgValidatorCore(
        OrgValidatorCore.Membership[] memory _roleMemberships,
        OrgValidatorCore.Permission[] memory _orgPermissions,
        string memory _orgName
    ) public returns (address) {
        OrgValidatorCore proxy = OrgValidatorCore(address(new TransparentStaticProxy(implementation)));
        proxy.initialize(_roleMemberships, _orgPermissions, _orgName);
        emit OrgValidatorCoreCreated(address(proxy), _orgName, _roleMemberships, _orgPermissions);
        return address(proxy);
    }
}
