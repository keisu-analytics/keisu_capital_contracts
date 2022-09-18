// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "src/factory/OrgValidatorCoreFactory.sol";
import "src/factory/SafeCoreFactory.sol";

contract DeployScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        OrgValidatorCoreFactory validatorfactory = new OrgValidatorCoreFactory();
        SafeCoreFactory safefactory = new SafeCoreFactory();

        vm.stopBroadcast();
    }
}
