// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "src/factory/OrgValidatorCoreFactory.sol";
import "src/factory/SafeCoreFactory.sol";
import "src/core/OrgValidatorCore.sol";
contract CreateSafeScript is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        SafeCoreFactory factorySafe = SafeCoreFactory(0x82EdF737415A57c676527477b13e4a1a5d7212e1);

        factorySafe.createSafeCore(address(0x5FF28a8864afc9Ae0d5eb1E8245FC95F93F11344), "Safe3");

        vm.stopBroadcast();
    }
}
