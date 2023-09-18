# Ethereum RPC &nbsp;[![GitHub license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/internet-computer-protocol/ic-eth-rpc/issues)

> #### Interact with [EVM blockchains](https://chainlist.org/?testnets=true) from the [Internet Computer](https://internetcomputer.org/).

---

## Overview

**Ethereum RPC** is an Internet Computer canister smart contract for communicating with [Ethereum](https://ethereum.org/en/) and other [EVM blockchains](https://chainlist.org/?testnets=true) using an [on-chain API](./API.md). 

This canister facilitates API requests to JSON-RPC services such as [CloudFlare](https://www.cloudflare.com/en-gb/web3/), [Alchemy](https://www.alchemy.com/), or [Gateway.fm](https://gateway.fm/) using [HTTPS outcalls](https://internetcomputer.org/docs/current/developer-docs/integrations/http_requests/). This enables functionality similar to traditional Ethereum dApps, including querying Ethereum smart contract states and submitting raw transactions.

Beyond the Ethereum blockchain, this canister also supports Polygon, Avalanche, and other popular EVM networks. Check out [this webpage](https://chainlist.org/?testnets=true) for a list of all supported networks and RPC providers.

## Canisters

* Low-cost testing: [6yxaq-riaaa-aaaap-abkpa-cai](https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.ic0.app/?id=6yxaq-riaaa-aaaap-abkpa-cai)

## Quick Start

Add the following to your `dfx.json` config file (replace `remote.id.ic` with any option from the list of available canisters above):

```json
{
  "canisters": {
    "ic_eth": {
      "type": "custom",
      "candid": "https://github.com/internet-computer-protocol/ic-eth-rpc/releases/latest/download/ic_eth.did",
      "wasm": "https://github.com/internet-computer-protocol/ic-eth-rpc/releases/latest/download/ic_eth_dev.wasm.gz",
      "remote": {
        "id": {
          "ic": "6yxaq-riaaa-aaaap-abkpa-cai"
        }
      }
    }
  }
}
```

Run the following commands to run the canister in your local environment:

```sh
# Start the local replica
dfx start --background

# Deploy the `ic_eth` canister
dfx deploy ic_eth

# Call the `eth_gasPrice` JSON-RPC method
dfx canister call ic_eth request '(variant {Url="https://cloudflare-eth.com/v1/mainnet"}, "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}", 1000)' --wallet $(dfx identity get-wallet) --with-cycles 600000000
```

## Examples

### Ethereum RPC (local replica)
```bash
# Use a custom provider
dfx canister call ic_eth --wallet $(dfx identity get-wallet) --with-cycles 600000000 request '(variant {Url="https://cloudflare-eth.com"},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)'
dfx canister call ic_eth --wallet $(dfx identity get-wallet) --with-cycles 600000000 request '(variant {Url="https://ethereum.publicnode.com"},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)'

# Register your own provider
dfx canister call ic_eth register_provider '(record { chain_id=1; base_url="https://cloudflare-eth.com"; credential_path="/v1/mainnet"; cycles_per_call=10; cycles_per_message_byte=1; })'

# Use a specific EVM chain
dfx canister call ic_eth --wallet $(dfx identity get-wallet) --with-cycles 600000000 request '(variant {Chain=0x1},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)'
```

### Ethereum RPC (IC mainnet)
```bash
dfx canister --network ic call ic_eth --wallet $(dfx identity --network ic get-wallet) --with-cycles 600000000 request '(variant {Url="https://cloudflare-eth.com"},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)'
dfx canister --network ic call ic_eth --wallet $(dfx identity --network ic get-wallet) --with-cycles 600000000 request '(variant {Url="https://ethereum.publicnode.com"},"{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",1000)'
```

### Authorization (local replica)

```bash
PRINCIPAL=$(dfx identity get-principal)
dfx canister call ic_eth authorize "(principal \"$PRINCIPAL\", variant { RegisterProvider })"
dfx canister call ic_eth get_authorized '(variant { RegisterProvider })'
dfx canister call ic_eth deauthorize "(principal \"$PRINCIPAL\", variant { RegisterProvider })"
```

## Contributing

Contributions are welcome! Please check out the [contributor guidelines](https://github.com/internet-computer-protocol/ic-eth-rpc/blob/main/.github/CONTRIBUTING.md) for more information.

Run the following commands to set up a local development environment:

```bash
# Clone the repository
git clone https://github.com/internet-computer-protocol/ic-eth-rpc
cd ic-eth-rpc

# Deploy to the local replica
dfx start --background
dfx deploy
```

## Learn More

* [How this canister works behind the scenes](https://github.com/internet-computer-protocol/ic-eth-rpc/blob/main/DeepDive.md)
* [Candid interface](https://github.com/internet-computer-protocol/ic-eth-rpc/blob/main/candid/ic_eth.did)
* [Detailed API documentation](https://github.com/internet-computer-protocol/ic-eth-rpc/blob/main/API.md)

## Related Projects

* [IC 🔗 ETH](https://github.com/dfinity/ic-eth-starter): a full-stack starter project for calling Ethereum smart contracts from an IC dApp.
* [Bitcoin canister](https://github.com/dfinity/bitcoin-canister): interact with the Bitcoin blockchain from the Internet Computer.
