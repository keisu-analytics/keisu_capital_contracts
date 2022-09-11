// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract OrgValidatorCore is EIP712 {
    struct Signature {
        uint256 v;
        uint256 r;
        uint256 s;
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

    struct Membership {
        address member;
        uint256 role;
    }
    string public orgName;
    //Role id 0 refers to the Permissions template being used
    //Role id 1 refers to the Policies template being used
    mapping(uint256 => mapping(address => bool)) public roleMemberships;
    mapping(uint256 => uint256) public orgPermissions;
    mapping(address => mapping(uint256 => uint256)) public safePermissions;
    //prevent replay
    mapping(address => uint256) public nonce;
    mapping (uint256 => mapping (uint256 => uint256)) public permissionsTemplates;
    uint256 public permissionTemplatePointer;
    mapping (uint256 => mapping (uint256 => uint256)) public policyTemplates;
    uint256 public policyTemplatePointer;

    error previouslyInitialized();

    constructor() payable EIP712("Keisu Capital", "0.1") {}

    //DO NOT override roles 0-1 or funds will be locked forever
    //there is validation for this to prevent attacks in editing functions after this
    function initialize(
        Membership[] memory _roleMemberships,
        Permission[] memory _orgPermissions,
        string memory _orgName
    ) public {
        if (permissionTemplatePointer != 0) {
            revert previouslyInitialized();
        }
        orgName = _orgName;
        for (uint256 i = 0; i < _roleMemberships.length; ++i) {
            roleMemberships[_roleMemberships[i].role][
                _roleMemberships[i].member
            ] = true;
        }

        for (uint256 i = 0; i < _orgPermissions.length; ++i) {
            permissionsTemplates[0][_orgPermissions[i].role] = _orgPermissions[i]
                .confirmations;
        }
    }

    function validateAuthorizationOrg() internal {
        unchecked {
                    address recoveredAddress = ecrecover(
                        keccak256(
                            abi.encodePacked(
                                "\x19\x01",
                                _domainSeparatorV4(),
                                keccak256(
                                    abi.encode(
                                        keccak256(
                                            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                        ),
                                        owner,
                                        spender,
                                        value,
                                        nonces[owner]++,
                                        deadline
                                    )
                                )
                            )
                        ),
                        v,
                        r,
                        s
                    );

            }
}
