// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes);

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    IEntryPoint private immutable i_entryPoint;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     *
     * @notice the Entry Point address can only call certain functions, such as validateUserOp.
     */
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    /**
     * @notice either the Entry Point or owner can call certain functions. For example, when executing a call
     * The owner accessability isn't necessarily required, but provides flexibility. For example, if needing to move funds around.
     * In this circumstance, the owner would pay the gas fees.
     */
    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     *
     * @param entryPoint the EIP-4337 Entry Point contract
     */
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                                EXTERNAL
    //////////////////////////////////////////////////////////////*/

    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    /**
     * @notice called by Entry Point, making this contract validate the signature of the User Operation. We check whether the signature matched the owner.
     * It could, however, be multiple people. For example instead of the owner solely being allowed to send User Operations,
     * we could check that multiple people signed it - which may be required in certain circumstances.
     * @param userOp the User Operation sent to the entry point from the bundler - originally composed by the signer off-chain.
     * @param userOpHash the EIP-4337 hash of the User Operation.
     * @param missingAccountFunds the required prefund paid to be sent to the Entry Point contract (see _payPreFund)
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        // validateNonce()
        _payPrefund(missingAccountFunds);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Recovers the signer from EIP-191 and checks to see if it matches the owner.
     * @param userOp the User Operation from the off-chain sender -> Bundler
     * @param userOpHash The EIP-4337 hash of the User Operation
     * @return validationData Whether the signature was valid. In this case, whether the signature came from the owner.
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED; // 1
        }
        return SIG_VALIDATION_SUCCESS; // 0
    }

    /**
     * @notice Pays the Entry Point the Pre-Fund. As the call comes from validateSignature, which is called by the Entry Point, the msg.sender will be the Entry Point.
     * The Pre-Fund ensures that the Entry Point has sufficient funds to pay for the call from the execute function.
     * @param missingAccountFunds the prefund amount required
     */
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Gets the Entry Point address
     */
    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
