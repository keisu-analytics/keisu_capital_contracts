// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/core/OrgValidatorCore.sol";
import "../src/factory/OrgValidatorCoreFactory.sol";

contract OrgValidatorCoreTest is Test {
    OrgValidatorCoreFactory public factory;
    OrgValidatorCore public validator;

    function setUp() public {
        factory = new OrgValidatorCoreFactory();
        OrgValidatorCore.Membership[] memory memberships = new OrgValidatorCore.Membership[](10);
        OrgValidatorCore.Permission[] memory permissions = new OrgValidatorCore.Permission[](4);
        uint256 k = 1;
        for (uint256 i = 0; i < 4; i++) {
            permissions[i] = OrgValidatorCore.Permission(uint128(i + 2), uint128(i + 1));
            for (uint256 j = 0; j < i + 1; j++) {
                memberships[k - 1] = OrgValidatorCore.Membership(vm.addr(k), i + 2);
                k++;
            }
        }
        //display memberships & permissions optionally with flag '-vv'
        for (uint256 i = 0; i < memberships.length; i++) {
            console2.log(memberships[i].member, memberships[i].role);
        }
        for (uint256 i = 0; i < permissions.length; i++) {
            console2.log(permissions[i].role, permissions[i].confirmations);
        }
        validator = OrgValidatorCore(factory.createOrgValidatorCore(memberships, permissions, "OrgName"));
    }

    function getMessageMembership(
        OrgValidatorCore.Membership[] memory changes,
        uint256 privateKey,
        uint256 role
    ) public returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    validator.domainSeperator(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "authorizeMembershipChanges(address targetOrg,Membership[] changes,uint256 actingRole,address signer,uint256 nonce)"
                            ),
                            address(validator),
                            changes,
                            uint256(role),
                            vm.addr(privateKey),
                            validator.nonces(vm.addr(privateKey))
                        )
                    )
                )
            );
    }

    function getMessagePermission(
        OrgValidatorCore.Permission[] memory changes,
        uint256 privateKey,
        uint256 role
    ) public returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    validator.domainSeperator(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "authorizePermissionChanges(address targetOrg,Permission[] changes,uint256 actingRole,address signer,uint256 nonce)"
                            ),
                            address(validator),
                            changes,
                            uint256(role),
                            vm.addr(privateKey),
                            validator.nonces(vm.addr(privateKey))
                        )
                    )
                )
            );
    }
    function testSanity() public {
        assertEq(validator.orgName(), "OrgName");
    }

    function test1of1MembershipEdit() public {
        OrgValidatorCore.Membership[] memory changes = new OrgValidatorCore.Membership[](1);
        changes[0] = OrgValidatorCore.Membership(vm.addr(100000), 100000);
        OrgValidatorCore.Signature[] memory signatures = new OrgValidatorCore.Signature[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, getMessageMembership(changes, 1, 2));
        signatures[0] = OrgValidatorCore.Signature(2, vm.addr(1), v, r, s);
        validator.editMembership(changes, signatures);
        assertEq(validator.roleMemberships(100000, vm.addr(100000)), true);
    }

    function test4of4MembershipEdit() public {
        OrgValidatorCore.Membership[] memory changes = new OrgValidatorCore.Membership[](1);
        changes[0] = OrgValidatorCore.Membership(vm.addr(100000), 100000);
        OrgValidatorCore.Signature[] memory signatures = new OrgValidatorCore.Signature[](4);
        for (uint256 i = 0; i < 4; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 7, getMessageMembership(changes, i + 7, 5));
            signatures[i] = OrgValidatorCore.Signature(5, vm.addr(i + 7), v, r, s);
        }
        validator.editMembership(changes, signatures);
        assertEq(validator.roleMemberships(100000, vm.addr(100000)), true);
    }

    function test1of1PermissionEdit() public {
        OrgValidatorCore.Permission[] memory changes = new OrgValidatorCore.Permission[](1);
        changes[0] = OrgValidatorCore.Permission(100000, 1);
        OrgValidatorCore.Signature[] memory signatures = new OrgValidatorCore.Signature[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, getMessagePermission(changes, 1, 2));
        signatures[0] = OrgValidatorCore.Signature(2, vm.addr(1), v, r, s);
        validator.editPermission(changes, signatures);
        assertEq(validator.orgPermissions(100000), 1);
    }

    function test4of4PermissionEdit() public {
        OrgValidatorCore.Permission[] memory changes = new OrgValidatorCore.Permission[](1);
        changes[0] = OrgValidatorCore.Permission(100000, 1);
        OrgValidatorCore.Signature[] memory signatures = new OrgValidatorCore.Signature[](4);
        for (uint256 i = 0; i < 4; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 7, getMessagePermission(changes, i + 7, 5));
            signatures[i] = OrgValidatorCore.Signature(5, vm.addr(i + 7), v, r, s);
        }        
        validator.editPermission(changes, signatures);
        assertEq(validator.orgPermissions(100000), 1);        
    }
}
