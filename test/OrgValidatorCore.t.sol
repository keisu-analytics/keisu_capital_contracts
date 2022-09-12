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
        uint256 k = 0;
        for (uint256 i = 0; i < 4; i++) {
            permissions[i] = OrgValidatorCore.Permission(uint128(i + 2), uint128(i + 1));
            for (uint256 j = 0; j < i + 1; j++) {
                memberships[k] = OrgValidatorCore.Membership(vm.addr(j + 1), i + 2);
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

    function testSanity() public {
        assertEq(validator.orgName(), "OrgName");
    }

    function test1of1MembershipEdit() public {
        OrgValidatorCore.Membership[] memory changes = new OrgValidatorCore.Membership[](1);
        changes[0] = OrgValidatorCore.Membership(vm.addr(100000), 100000);
        OrgValidatorCore.Signature[] memory signatures = new OrgValidatorCore.Signature[](1);

        bytes32 message = keccak256(
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
                        uint256(2),
                        vm.addr(1),
                        uint256(0)
                    )
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);
        signatures[0] = OrgValidatorCore.Signature(2, vm.addr(1), v, r, s);
        validator.editMembership(changes, signatures);
        assertEq(validator.roleMemberships(100000, vm.addr(100000)), true);
    }
}
