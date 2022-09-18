// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/core/SafeCore.sol";
import "../src/core/OrgValidatorCore.sol";
import "../src/factory/SafeCoreFactory.sol";
import "../src/factory/OrgValidatorCoreFactory.sol";

contract SafeCoreTest is Test {
    OrgValidatorCoreFactory public factoryValidator;
    SafeCoreFactory public factorySafe;
    OrgValidatorCore public validator;
    SafeCore public safe;

    function setUp() public {
        factoryValidator = new OrgValidatorCoreFactory();
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
        validator = OrgValidatorCore(factoryValidator.createOrgValidatorCore(memberships, permissions, "OrgName"));
        factorySafe = new SafeCoreFactory();
        safe = SafeCore(factorySafe.createSafeCore(address(validator), "SafeName"));
        vm.deal(address(safe), 1 ether);
    }

    function getMessageTransaction(
        IOrgValidatorCore.Transaction memory transaction,
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
                                "authorizeTransaction(address targetSafe,Transaction transaction,uint256 actingRole,address signer,uint256 nonce)"
                            ),
                            address(safe),
                            abi.encode(transaction),
                            uint256(role),
                            vm.addr(privateKey),
                            validator.nonces(vm.addr(privateKey))
                        )
                    )
                )
            );
    }

    function test1of1Transaction() public {
        IOrgValidatorCore.Transaction memory transaction = IOrgValidatorCore.Transaction(vm.addr(1), 1 ether, "");
        IOrgValidatorCore.Signature[] memory signatures = new IOrgValidatorCore.Signature[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, getMessageTransaction(transaction, 1, 2));
        signatures[0] = IOrgValidatorCore.Signature(2, vm.addr(1), v, r, s);
        safe.execTransaction(transaction, signatures);
        assertEq(vm.addr(1).balance, 1 ether);
    }

    function test4of4Transaction() public {
        IOrgValidatorCore.Transaction memory transaction = IOrgValidatorCore.Transaction(vm.addr(1), 1 ether, "");
        IOrgValidatorCore.Signature[] memory signatures = new IOrgValidatorCore.Signature[](4);
        for (uint256 i = 0; i < 4; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 7, getMessageTransaction(transaction, i + 7, 5));
            signatures[i] = IOrgValidatorCore.Signature(5, vm.addr(i + 7), v, r, s);
        }
        safe.execTransaction(transaction, signatures);
        assertEq(vm.addr(1).balance, 1 ether);
    }
}
