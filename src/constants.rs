use cketh_common::eth_rpc_client::providers::{EthereumProvider, SepoliaProvider};

pub const INGRESS_OVERHEAD_BYTES: u128 = 100;
pub const INGRESS_MESSAGE_RECEIVED_COST: u128 = 1_200_000;
pub const INGRESS_MESSAGE_BYTE_RECEIVED_COST: u128 = 2_000;
pub const HTTP_OUTCALL_REQUEST_COST: u128 = 400_000_000;
pub const HTTP_OUTCALL_BYTE_RECEIEVED_COST: u128 = 100_000;

pub const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000;

pub const STRING_STORABLE_MAX_SIZE: u32 = 100;
pub const AUTH_SET_STORABLE_MAX_SIZE: u32 = 1000;
pub const WASM_PAGE_SIZE: u64 = 65536;

pub const DEFAULT_NODES_IN_SUBNET: u32 = 13;
pub const DEFAULT_OPEN_RPC_ACCESS: bool = true;

// Providers used by default (when passing `null` with `CandidRpcSource`)
pub const DEFAULT_ETHEREUM_PROVIDER: EthereumProvider = EthereumProvider::Ankr;
pub const DEFAULT_SEPOLIA_PROVIDER: SepoliaProvider = SepoliaProvider::PublicNode;

pub const CONTENT_TYPE_HEADER: &str = "Content-Type";

pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_SEPOLIA_CHAIN_ID: u64 = 11155111;

pub const SERVICE_HOSTS_ALLOWLIST: &[&str] = &[
    "cloudflare-eth.com",
    "ethereum.publicnode.com",
    "ethereum-goerli.publicnode.com",
    "ethereum-sepolia.publicnode.com",
    "ethereum.blockpi.network",
    "ethereum-sepolia.blockpi.network",
    "eth-mainnet.g.alchemy.com",
    "eth-goerli.g.alchemy.com",
    "rpc.flashbots.net",
    "eth-mainnet.blastapi.io",
    "ethereumnodelight.app.runonflux.io",
    "eth.nownodes.io",
    "rpc.ankr.com",
    "mainnet.infura.io",
    "eth.getblock.io",
    "rpc.kriptonio.com",
    "rpc.sepolia.org",
    "api.0x.org",
    "erigon-mainnet--rpc.datahub.figment.io",
    "archivenode.io",
    "eth-mainnet.nodereal.io",
    "ethereum-mainnet.s.chainbase.online",
    "eth.llamarpc.com",
    "ethereum-mainnet-rpc.allthatnode.com",
    "api.zmok.io",
    "in-light.eth.linkpool.iono",
    "api.mycryptoapi.com",
    "mainnet.eth.cloud.ava.dono",
    "eth-mainnet.gateway.pokt.network",
];
