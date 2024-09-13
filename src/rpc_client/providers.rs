use evm_rpc_types::{EthMainnetService, EthSepoliaService, L2MainnetService, RpcService};

pub(crate) const MAINNET_PROVIDERS: &[RpcService] = &[
    RpcService::EthMainnet(EthMainnetService::Alchemy),
    RpcService::EthMainnet(EthMainnetService::Ankr),
    RpcService::EthMainnet(EthMainnetService::PublicNode),
    RpcService::EthMainnet(EthMainnetService::Cloudflare),
    RpcService::EthMainnet(EthMainnetService::Llama),
];

pub(crate) const SEPOLIA_PROVIDERS: &[RpcService] = &[
    RpcService::EthSepolia(EthSepoliaService::Alchemy),
    RpcService::EthSepolia(EthSepoliaService::Ankr),
    RpcService::EthSepolia(EthSepoliaService::BlockPi),
    RpcService::EthSepolia(EthSepoliaService::PublicNode),
    RpcService::EthSepolia(EthSepoliaService::Sepolia),
];

pub(crate) const ARBITRUM_PROVIDERS: &[RpcService] = &[
    RpcService::ArbitrumOne(L2MainnetService::Alchemy),
    RpcService::ArbitrumOne(L2MainnetService::Ankr),
    RpcService::ArbitrumOne(L2MainnetService::PublicNode),
    RpcService::ArbitrumOne(L2MainnetService::Llama),
];

pub(crate) const BASE_PROVIDERS: &[RpcService] = &[
    RpcService::BaseMainnet(L2MainnetService::Alchemy),
    RpcService::BaseMainnet(L2MainnetService::Ankr),
    RpcService::BaseMainnet(L2MainnetService::PublicNode),
    RpcService::BaseMainnet(L2MainnetService::Llama),
];

pub(crate) const OPTIMISM_PROVIDERS: &[RpcService] = &[
    RpcService::OptimismMainnet(L2MainnetService::Alchemy),
    RpcService::OptimismMainnet(L2MainnetService::Ankr),
    RpcService::OptimismMainnet(L2MainnetService::PublicNode),
    RpcService::OptimismMainnet(L2MainnetService::Llama),
];

// Default RPC services for unknown EVM network
pub(crate) const UNKNOWN_PROVIDERS: &[RpcService] = &[];
