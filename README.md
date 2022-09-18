# Keisu Capital Contracts

Contracts used in the Keisu Capital custody system.

## Commands
Compile contracts

`forge build`

Compile and test

`forge test`

Deploy factory contracts (replace GOERLI with network of choice)

`source .env`

`forge script script/DeployFactory.s.sol:DeployScript --rpc-url $GOERLI_RPC_URL --broadcast -vvvv`

## Environment Variables

`MAINNET_RPC_URL` - RPC URL for the Ethereum Mainnet (1)

`GOERLI_RPC_URL` - RPC URL for the Goerli Testnet (5)

`PRIVATE_KEY` - Private key of the deployer account

## Contracts

```ml
factory
├── OrgValidatorCoreFactory — "Factory for OrgValidatorCore (using TransparentStaticProxy)"
├── SafeCoreFactory — "Factory for SafeCore (using TransparentStaticProxy)"
proxy
├─ TransparentStaticProxy — "Simple, non-upgradeable transparent proxy"
core
├─ OrgValidatorCore — "Parent registry for an org that validates authorizations from child safe contracts"
├─ SafeCore — "Validates signatures with parent org contract, then makes a specified call"
```