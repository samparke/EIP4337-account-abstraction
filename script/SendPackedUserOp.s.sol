// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    function run() public {}

    /**
     * @notice Generates the PackedUserOperation. It first generates the unsigned user operation from _generateUnsignedUserOperation.
     * It then combines this with the signature from the off-chain user.
     * @param callData The calldata we are attempting to execute from the Entry Point. For example, MinimalAccount.execute(calldata).
     * @param config The configuration for the chain we are on, which contains the Entry Point address and the account (which will be the off-chain user)
     * @dev We generate the hash for the unsigned user operation, format it correctly into the digest, and sign it with the off-chain users private key.
     * @return Return the entire User Operation, including the signature. This will be used when our Minimal Account recovers the signature,
     * and compares with the off-chain users signer.
     */
    function generateSignedUserOperation(
        bytes memory callData,
        HelperConfig.NetworkConfig memory config,
        address minimalAccount
    ) public view returns (PackedUserOperation memory) {
        // generate unsigned data
        uint256 nonce = vm.getNonce(minimalAccount) - 1;
        PackedUserOperation memory userOp = _generateUnsignedUserOperation(callData, minimalAccount, nonce);

        // get userOp hash
        bytes32 userOpHash = IEntryPoint(config.entryPoint).getUserOpHash(userOp);
        // correctly formatted hash
        bytes32 digest = userOpHash.toEthSignedMessageHash();
        // sign
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        if (block.chainid == 31337) {
            (v, r, s) = vm.sign(ANVIL_DEFAULT_KEY, digest);
        } else {
            (v, r, s) = vm.sign(config.account, digest);
        }

        userOp.signature = abi.encodePacked(r, s, v);
        return userOp;
    }

    /**
     *
     * @param callData The calldata we are attempting to execute from the Entry Point. For example, MinimalAccount.execute(calldata).
     * @param sender The Minimal Account (AA smart contract)
     * @param nonce The incremented number to avoid replayed transactions
     * @return PackedUserOperation The PackedUserOperation struct without the signature field.
     */
    function _generateUnsignedUserOperation(bytes memory callData, address sender, uint256 nonce)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        uint128 verificationGasLimit = 16777216;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;

        // struct PackedUserOperation {
        //     address sender;
        //     uint256 nonce;
        //     bytes initCode;
        //     bytes callData;
        //     bytes32 accountGasLimits;
        //     uint256 preVerificationGas;
        //     bytes32 gasFees;
        //     bytes paymasterAndData;
        //     bytes signature;
        // }

        return PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: verificationGasLimit,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}
