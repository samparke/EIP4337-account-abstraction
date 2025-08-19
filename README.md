## EIP-4337 Account Abstraction

**This project:**

- Provides a Minimal Account Abstraction wallet on Ethereum and ZkSync.

What it does:

- Provides a minimal smart contract account that works with the EIP-4337 EntryPoint.
- Validates that a transaction (UserOperation) is signed by the account owner.
- If the signature is valid, the account executes the transaction.
- Effectively, anyone can relay a transaction on behalf of the owner, as long as it carries the correct owner signature.

Flow on Ethereum:

- Off-chain, the owner signs a UserOperation.
- A bundler submits the UserOperation to the EntryPoint contract.
- The EntryPoint verifies the signature via the Minimal Account.
- If valid, the EntryPoint funds the gas and executes the transaction through the account.

Flow on ZkSync:

- Owner signs a zkSync Transaction off-chain.
- Bootloader calls validateTransaction, which:
  - Increments nonce (via NonceHolder).
  - Checks account balance for fees.
- Verifies the signature matches the owner.
  - Bootloader calls payForTransaction – account pays fees.
  - Bootloader calls executeTransaction:
  - If deploying, uses Deployer system contract.
  - Otherwise, performs a normal call (to, value, data).

The account executes the transaction if signed by the owner and fees are covered.
