// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "forge-std/console2.sol";
contract OrgValidatorCore {
    struct Signature {
        uint256 actingRole;
        address signer;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
    struct Permission {
        uint128 role;
        uint128 confirmations;
    }
    //optional additional required confirmations from role
    //policy struct is functionally same as permission, but wanted to differentiate
    struct Policy {
        uint128 role;
        uint128 requiredConfirmations;
    }

    struct PolicyChange {
        uint64 index;
        uint64 role;
        uint64 requiredConfirmations;
    }
    struct Membership {
        address member;
        uint256 role;
    }

    struct ConfirmationCount {
        uint128 role;
        uint128 count;
    }
    string public orgName;
    bytes32 public domainSeperator;
    //Role id 0 refers to the Permissions template being used
    //Role id 1 refers to the Policies template being used
    mapping(uint256 => mapping(address => bool)) public roleMemberships;
    mapping(uint256 => uint256) public orgPermissions;
    Policy[] public orgPolicies;
    mapping(address => mapping(uint256 => uint256)) public safePermissions;
    mapping(address => mapping(uint256 => Policy[])) public safePolicies;
    //prevent replay
    mapping(address => uint256) public nonces;
    mapping(uint256 => mapping(uint256 => uint256)) public permissionsTemplates;
    uint256 public permissionTemplatePointer;
    mapping(uint256 => Policy[]) public policyTemplates;
    uint256 public policyTemplatePointer;

    error previouslyInitialized();
    error invalidSignature();
    error invalidRole();
    error policyNotMet(uint256 role);
    error insufficientConfirmations();

    //DO NOT override roles 0-1 or funds will be locked forever
    //there is validation for this to prevent attacks in editing functions after this
    function initialize(
        Membership[] memory _roleMemberships,
        Permission[] memory _orgPermissions,
        string memory _orgName
    ) public {
        if (domainSeperator != bytes32(0)) {
            revert previouslyInitialized();
        }
        domainSeperator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(_orgName)),
                keccak256("0.1"),
                block.chainid,
                address(this)
            )
        );
        orgName = _orgName;
        for (uint256 i = 0; i < _roleMemberships.length; ++i) {
            roleMemberships[_roleMemberships[i].role][_roleMemberships[i].member] = true;
        }

        for (uint256 i = 0; i < _orgPermissions.length; ++i) {
            permissionsTemplates[0][_orgPermissions[i].role] = _orgPermissions[i].confirmations;
        }
    }

    function modifyRoleMembership(Membership[] memory _roleMemberships) internal {
        for (uint256 i = 0; i < _roleMemberships.length; ++i) {
            roleMemberships[_roleMemberships[i].role][_roleMemberships[i].member] = !roleMemberships[_roleMemberships[i].role][
                _roleMemberships[i].member
            ];
        }
    }

    function modifyPermissionsOrg(Permission[] memory changes) internal {
        for (uint256 i = 0; i < changes.length; ++i) {
            orgPermissions[changes[i].role] = changes[i].confirmations;
        }
    }

    function modifyPoliciesOrg (PolicyChange[] memory changes) internal {
        for (uint256 i = 0; i < changes.length; ++i) {
            //allocate space in array if needed
            for (uint256 j = orgPolicies.length; j <= changes[i].index; ++j) {
                orgPolicies.push(Policy(0, 0));
            }
            orgPolicies[changes[i].index].role = changes[i].role;
            orgPolicies[changes[i].index].requiredConfirmations = changes[i].requiredConfirmations;
        }
    }



    function isMember(uint256 _role, address _member) public view returns (bool) {
        return roleMemberships[_role][_member];
    }

    //@TODO make this function more efficient (O(n^2) bad)
    //gets number of confirmations by role for an array of signatures
    //signatures should be validated before calling this function
    function getRoleCounts(Signature[] memory signatures) internal pure returns (ConfirmationCount[] memory) {
        ConfirmationCount[] memory confirmationCounts = new ConfirmationCount[](signatures.length);
        //loop through signatures and load into confirmationCounts
        for (uint256 i = 0; i < signatures.length; ++i) {
            //try to find existing role in confirmationCounts, if not just put it at the end
            uint256 confirmationCountIndex = confirmationCounts.length - 1;
            for (uint256 j = 0; j < confirmationCounts.length; ++j) {
                if (confirmationCounts[j].role == signatures[i].actingRole) {
                    confirmationCountIndex = j;
                    break;
                }
            }
            //initialize role if first signature (from that role)
            if (confirmationCounts[confirmationCountIndex].role == 0) {
                confirmationCounts[confirmationCountIndex].role = uint128(signatures[i].actingRole);
            }
            confirmationCounts[confirmationCountIndex].count++;
        }
        return confirmationCounts;
    }

    //@TODO make this function more efficient (O(n^2) bad)
    function validatePermissionsOrg(ConfirmationCount[] memory confirmationCounts) internal view {
        //loop through policy template, then policies and check if they are met
        for (uint256 i = 0; i < policyTemplates[orgPermissions[1]].length; ++i) {
            bool met;
            for (uint256 j = 0; j < confirmationCounts.length; ++j) {
                if (confirmationCounts[j].role == policyTemplates[orgPermissions[1]][i].role) {
                    if (confirmationCounts[j].count < policyTemplates[orgPermissions[1]][i].requiredConfirmations) {
                        revert policyNotMet(confirmationCounts[j].role);
                    }
                    met = true;
                    break;
                }
            }
            if (!met) {
                revert policyNotMet(policyTemplates[orgPermissions[1]][i].role);
            }
        }
        for (uint256 i = 0; i < orgPolicies.length; ++i) {
            bool met;
            for (uint256 j = 0; j < confirmationCounts.length; ++j) {
                if (confirmationCounts[j].role == orgPolicies[i].role) {
                    if (confirmationCounts[j].count < orgPolicies[i].requiredConfirmations) {
                        revert policyNotMet(confirmationCounts[j].role);
                    }
                    met = true;
                    break;
                }
                if (!met) {
                    revert policyNotMet(orgPolicies[i].role);
                }
            }
        }
        //loop through confirmationCounts and look for something that has sufficient confirmations
        //check template first, then additional permissions
        for (uint256 i = 0; i < confirmationCounts.length; ++i) {
            if (
                confirmationCounts[i].count >= permissionsTemplates[orgPermissions[0]][confirmationCounts[i].role] ||
                confirmationCounts[i].count >= orgPermissions[confirmationCounts[i].role]
            ) {
                return;
            }
        }
        revert insufficientConfirmations();
    }
    function recoverPermit(bytes memory changes, string memory methodString, Signature memory signature) internal returns (address) {
        return (
        ecrecover(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeperator,
                    keccak256(
                        abi.encode(
                            keccak256(
                                bytes(methodString)
                            ),
                            address(this),
                            changes,
                            signature.actingRole,
                            signature.signer,
                            nonces[signature.signer]++
                        )
                    )
                )
            ),
            signature.v,
            signature.r,
            signature.s
        )
    );       
    }

    function validateAuthorizationMembership(Membership[] memory changes, Signature[] memory signatures) internal {
        unchecked {

            //validate and recover addresses from signatures
            for (uint256 i = 0; i < signatures.length; ++i) {

                address recoveredAddress = recoverPermit(abi.encode(changes), "authorizeMembershipChanges(address targetOrg,Membership[] changes,uint256 actingRole,address signer,uint256 nonce)", signatures[i]);
                //check if recovered address is a member of the role that signed
                if (recoveredAddress != signatures[i].signer) {
                    revert invalidSignature();
                }
                if (!isMember(signatures[i].actingRole, signatures[i].signer)) {
                    revert invalidRole();
                }
            }
            validatePermissionsOrg(getRoleCounts(signatures));
        }
    }

    function validateAuthorizationPermission(Permission[] memory changes, Signature[] memory signatures) internal {
        unchecked {
            //validate and recover addresses from signatures
            for (uint256 i = 0; i < signatures.length; ++i) {
                address recoveredAddress = recoverPermit(abi.encode(changes), "authorizePermissionChanges(address targetOrg,Permission[] changes,uint256 actingRole,address signer,uint256 nonce)", signatures[i]);
                if (recoveredAddress != signatures[i].signer) {
                    revert invalidSignature();
                }
                if (!isMember(signatures[i].actingRole, signatures[i].signer)) {
                    revert invalidRole();
                }
            }
            validatePermissionsOrg(getRoleCounts(signatures));
        }
    }    

    function validateAuthorizationPolicy(PolicyChange[] memory changes, Signature[] memory signatures) public {
        unchecked {
            //validate and recover addresses from signatures
            for (uint256 i = 0; i < signatures.length; ++i) {
                address recoveredAddress = recoverPermit(abi.encode(changes), "authorizePolicyChanges(address targetOrg,PolicyChange[] changes,uint256 actingRole,address signer,uint256 nonce)", signatures[i]);
                if (recoveredAddress != signatures[i].signer) {
                    revert invalidSignature();
                }
                if (!isMember(signatures[i].actingRole, signatures[i].signer)) {
                    revert invalidRole();
                }
            }
            validatePermissionsOrg(getRoleCounts(signatures));
        }

    }

    function editMembership(Membership[] memory changes, Signature[] memory signatures) public {
        validateAuthorizationMembership(changes, signatures);
        modifyRoleMembership(changes);
    }

    function editPermission(Permission[] memory changes, Signature[] memory signatures) public {
        validateAuthorizationPermission(changes, signatures);
        modifyPermissionsOrg(changes);
    }

    function editPolicy (PolicyChange[] memory changes, Signature[] memory signatures) public {
        validateAuthorizationPolicy(changes, signatures);
        modifyPoliciesOrg(changes);
    }
}
