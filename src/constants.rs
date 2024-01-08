use cketh_common::eth_rpc_client::providers::{EthMainnetService, EthSepoliaService};

pub const INGRESS_OVERHEAD_BYTES: u128 = 100;
pub const INGRESS_MESSAGE_RECEIVED_COST: u128 = 1_200_000;
pub const INGRESS_MESSAGE_BYTE_RECEIVED_COST: u128 = 2_000;
pub const HTTP_OUTCALL_REQUEST_COST: u128 = 400_000_000;
pub const HTTP_OUTCALL_BYTE_RECEIVED_COST: u128 = 100_000;

pub const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000;

pub const STRING_STORABLE_MAX_SIZE: u32 = 100;
pub const AUTH_SET_STORABLE_MAX_SIZE: u32 = 1000;
pub const WASM_PAGE_SIZE: u64 = 65536;

pub const NODES_IN_DEFAULT_SUBNET: u32 = 13;
pub const NODES_IN_FIDUCIARY_SUBNET: u32 = 28;
pub const DEFAULT_OPEN_RPC_ACCESS: bool = true;

// Providers used by default (when passing `null` with `CandidRpcSource`)
pub const DEFAULT_ETHEREUM_SERVICES: &[EthMainnetService] = &[
    EthMainnetService::Ankr,
    EthMainnetService::Cloudflare,
    EthMainnetService::PublicNode,
];
pub const DEFAULT_SEPOLIA_SERVICES: &[EthSepoliaService] = &[
    EthSepoliaService::Ankr,
    EthSepoliaService::PublicNode,
];

pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const CONTENT_TYPE_VALUE: &str = "application/json";

pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_SEPOLIA_CHAIN_ID: u64 = 11155111;

pub const SERVICE_HOSTS_BLOCKLIST: &[&str] = &[];
