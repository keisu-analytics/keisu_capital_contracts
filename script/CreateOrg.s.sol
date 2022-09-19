// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "src/factory/OrgValidatorCoreFactory.sol";
import "src/factory/SafeCoreFactory.sol";
import "src/core/OrgValidatorCore.sol";
contract CreateOrgScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        string memory mnemonic = vm.envString("MNEMONIC");
        vm.startBroadcast(deployerPrivateKey);
        OrgValidatorCoreFactory factoryValidator = OrgValidatorCoreFactory(0xA74Fa3447156d050315Ff606ae388e1377283Eba);
        OrgValidatorCore.Membership[] memory memberships = new OrgValidatorCore.Membership[](10);
        OrgValidatorCore.Permission[] memory permissions = new OrgValidatorCore.Permission[](4);
        uint32 k = 1;
        for (uint256 i = 0; i < 4; i++) {
            permissions[i] = OrgValidatorCore.Permission(uint128(i + 2), uint128(i + 1));
            for (uint256 j = 0; j < i + 1; j++) {
                memberships[k - 1] = OrgValidatorCore.Membership(vm.addr(vm.deriveKey(mnemonic, k)), i + 2);
                k++;
            }
        }
        factoryValidator.createOrgValidatorCore(memberships, permissions, "Org3");

        vm.stopBroadcast();
    }
}
