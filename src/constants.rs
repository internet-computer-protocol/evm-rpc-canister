use cketh_common::eth_rpc_client::providers::{
    EthMainnetService, EthSepoliaService, L2MainnetService,
};

// HTTP outcall cost calculation
// See https://internetcomputer.org/docs/current/developer-docs/gas-cost#special-features
pub const INGRESS_OVERHEAD_BYTES: u128 = 100;
pub const INGRESS_MESSAGE_RECEIVED_COST: u128 = 1_200_000;
pub const INGRESS_MESSAGE_BYTE_RECEIVED_COST: u128 = 2_000;
pub const HTTP_OUTCALL_REQUEST_BASE_COST: u128 = 3_000_000;
pub const HTTP_OUTCALL_REQUEST_PER_NODE_COST: u128 = 60_000;
pub const HTTP_OUTCALL_REQUEST_COST_PER_BYTE: u128 = 400;
pub const HTTP_OUTCALL_RESPONSE_COST_PER_BYTE: u128 = 800;

// Additional cost of operating the canister per subnet node
pub const CANISTER_OVERHEAD: u128 = 1_000_000;

// Cycles which must be passed with each RPC request in case the
// third-party JSON-RPC prices increase in the future (currently always refunded)
pub const COLLATERAL_CYCLES_PER_NODE: u128 = 10_000_000;

// Minimum number of bytes charged for a URL; improves consistency of costs between providers
pub const RPC_URL_MIN_COST_BYTES: u32 = 256;

pub const MINIMUM_WITHDRAWAL_CYCLES: u128 = 1_000_000_000;

pub const STRING_STORABLE_MAX_SIZE: u32 = 100;
pub const PROVIDER_MAX_SIZE: u32 = 256;
pub const RPC_SERVICE_MAX_SIZE: u32 = 256;
pub const AUTH_SET_STORABLE_MAX_SIZE: u32 = 1000;
pub const WASM_PAGE_SIZE: u64 = 65536;

pub const ETH_GET_LOGS_MAX_BLOCKS: u32 = 500;

pub const NODES_IN_STANDARD_SUBNET: u32 = 13;
pub const NODES_IN_FIDUCIARY_SUBNET: u32 = 28;
pub const DEFAULT_OPEN_RPC_ACCESS: bool = true;

pub const API_KEY_REPLACE_STRING: &str = "{API_KEY}";

// Providers used by default (when passing `null` with `RpcServices`)
pub const DEFAULT_ETH_MAINNET_SERVICES: &[EthMainnetService] = &[
    EthMainnetService::Ankr,
    EthMainnetService::Cloudflare,
    EthMainnetService::PublicNode,
];
pub const DEFAULT_ETH_SEPOLIA_SERVICES: &[EthSepoliaService] = &[
    EthSepoliaService::Ankr,
    EthSepoliaService::BlockPi,
    EthSepoliaService::PublicNode,
];
pub const DEFAULT_L2_MAINNET_SERVICES: &[L2MainnetService] = &[
    L2MainnetService::Ankr,
    L2MainnetService::BlockPi,
    L2MainnetService::PublicNode,
];

pub const CONTENT_TYPE_HEADER: &str = "Content-Type";
pub const CONTENT_TYPE_VALUE: &str = "application/json";

pub const ETH_MAINNET_CHAIN_ID: u64 = 1;
pub const ETH_SEPOLIA_CHAIN_ID: u64 = 11155111;
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42161;
pub const BASE_MAINNET_CHAIN_ID: u64 = 8453;
pub const OPTIMISM_MAINNET_CHAIN_ID: u64 = 10;

pub const SERVICE_HOSTS_BLOCKLIST: &[&str] = &[];
