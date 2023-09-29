# Deep Dive: [Ethereum RPC](https://github.com/internet-computer-protocol/ic-eth-rpc)

## How it Works

This canister provides a connection between the Internet Computer and the Ethereum network. For interactions that involve value transfer, such as in the context of cross-chain asset transfers, multiple Web2 JSON-RPC providers can be queried by a client to increase the assurance of correctness of the answer. This is a decision on the security model that is left to the client.

Authorized principals are permitted to register, update, and de-register so-called *providers*, each of which defines a registered API key for a specific Web2 JSON API service for a given chain id. It furthermore defines the cycles price to be paid when using this provider.	

This canister's API can be used in two different ways depending on the use case:	
* *Registered API key:* Client canisters use the canister's RPC API such that canister-registered API keys are used to interact with the Web2 API provider. This has the advantage that the maintainer of the client does not need to manage their own API keys with RPC providers, but simply uses the one registered in the canister.	
* *Client-provided API key:* Client canisters can provide their own API key with calls, e.g., to use APIs for which there are no registered providers available. This also helps reduce the quota usage for quota-limited API keys. The API providers to be used this way need to be on an allowlist of the canister.	
This gives the canister great flexibility of how it can be used in different deployment scenarios.	

At least the following deployment scenarios are supported by the API of this canister:	
* The IC community deploys the canister on an IC system subnet and hands control over to the NNS. The canister makes its API available to any canister on the IC as an infrastructure service. At least one API key with high-volume access quota should be registered as a provider in this scenario. Deployment on a system subnet gives the canister IPv4 access, which is currently not available on application subnets, and thus a substantially broader coverage of API providers.	
* A project can deploy the canister itself on an application subnet, use the project's own API keys, and limit access to the canister's API to project-specific canisters.	
* Anyone can deploy the canister on an application subnet for public use.	

**Note**: The canister has been designed to connect to the Ethereum blockchain from the Internet Computer, however, the canister may also be useful to connect to other EVM blockchains that support the same JSON-RPC API and follow standards of Ethereum.	

The API of the canister is specified through a [Candid interface specification](./candid/eth_rpc.did). Detailed API documentation is available [here](./API.md).

## Caveats

### API Keys are stored in the canister	

Registered API keys are available to IC nodes in plaintext.  While the canister memory is not exposed generally to users, it is available to node providers and to canister controllers.  In the future features such as SEV-SNP will enable privacy of canister memory, but until we have those features the API keys should not be considered to be entirely safe from leakage and potential misuse. API key providers should limit the scope of their API keys and monitor usage to detect any misuse.	

### Registered API providers should be aware that each API call will result in one service provider call per node in the subnet and that costs (and payment) is scaled accordingly	

Application subnets have some number of nodes (typically 13), so a `request` call will result in 13 HTTP outcalls using the registered API key. API providers should be aware of this when considering rate and operation limits.	

### Signed Transactions should be securely signed	

This canister takes pre-signed transactions e.g. for `eth_sendRawTransaction` and these should be signed in a secure way, for example using Threshold ECDSA or by signing the transaction in a secure manner offline.  In any case, private keys should not be stored in canisters because canister memory is (currently) not private from node providers.	

### JSON is not validated	

This canister does not validate the JSON passed to the ETH service.  Registered API key providers should be aware of this in case the back end service is vulnerable to a bad JSON request body.  Registered API providers should be aware that there are methods in the Ethereum RPC API specification which give access to the ETH node keys.  Public service providers tend to block these, but registered API providers should ensure that they are not giving access to private keys or other privileged operations.	

### Requests sent to service providers are subject to the service provider's privacy policy	

Users should be aware of the privacy policy of the service provider to which their requests are sent as some service providers have stronger privacy guarantees.	

### Idempotency issues because of one HTTP outcall per node in the subnet	

HTTP outcalls result in one HTTP outcall per node in the subnet and the results are then combined after filtering through a Transform function.  Some Ethereum RPC calls may not be idempotent or may vary which will cause the call to be reported as a failure as there will be no consensus on the result.  Furthermore this behavior may differ by service provider.  Users should be aware of this and use appropriate caution and/or a different solution.
