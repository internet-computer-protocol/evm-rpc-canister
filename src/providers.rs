use std::collections::HashMap;

use cketh_common::{
    eth_rpc::ProviderError,
    eth_rpc_client::providers::{
        EthMainnetService, EthSepoliaService, L2MainnetService, RpcApi, RpcService,
    },
};
use maplit::hashmap;

use crate::{
    constants::{
        ARBITRUM_ONE_CHAIN_ID, BASE_MAINNET_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        OPTIMISM_MAINNET_CHAIN_ID,
    },
    types::{Provider, ProviderId, ResolvedRpcService},
};

pub const ANKR_HOSTNAME: &str = "rpc.ankr.com";
pub const ALCHEMY_ETH_MAINNET_HOSTNAME: &str = "eth-mainnet.g.alchemy.com";
pub const ALCHEMY_ETH_SEPOLIA_HOSTNAME: &str = "eth-sepolia.g.alchemy.com";
pub const CLOUDFLARE_HOSTNAME: &str = "cloudflare-eth.com";
pub const BLOCKPI_ETH_MAINNET_HOSTNAME: &str = "ethereum.blockpi.network";
pub const BLOCKPI_ETH_SEPOLIA_HOSTNAME: &str = "ethereum-sepolia.blockpi.network";
pub const PUBLICNODE_ETH_MAINNET_HOSTNAME: &str = "ethereum-rpc.publicnode.com";
pub const PUBLICNODE_ETH_SEPOLIA_HOSTNAME: &str = "ethereum-sepolia-rpc.publicnode.com";
pub const ETH_SEPOLIA_HOSTNAME: &str = "rpc.sepolia.org";
pub const ALCHEMY_ARBITRUM_ONE_HOSTNAME: &str = "arb-mainnet.g.alchemy.com";
pub const BLOCKPI_ARBITRUM_ONE_HOSTNAME: &str = "arbitrum.blockpi.network";
pub const PUBLICNODE_ARBITRUM_ONE_HOSTNAME: &str = "arbitrum-one-rpc.publicnode.com";
pub const ALCHEMY_BASE_MAINNET_HOSTNAME: &str = "base-mainnet.g.alchemy.com";
pub const BLOCKPI_BASE_MAINNET_HOSTNAME: &str = "base.blockpi.network";
pub const PUBLICNODE_BASE_MAINNET_HOSTNAME: &str = "base-rpc.publicnode.com";
pub const ALCHEMY_OPT_MAINNET_HOSTNAME: &str = "opt-mainnet.g.alchemy.com";
pub const BLOCKPI_OPTIMISM_MAINNET_HOSTNAME: &str = "optimism.blockpi.network";
pub const PUBLICNODE_OPTIMISM_MAINNET_HOSTNAME: &str = "optimism-rpc.publicnode.com";
pub const LLAMA_ETH_MAINNET_HOSTNAME: &str = "eth.llamarpc.com";
pub const LLAMA_ARBITRUM_ONE_HOSTNAME: &str = "arbitrum.llamarpc.com";
pub const LLAMA_BASE_MAINNET_HOSTNAME: &str = "base.llamarpc.com";
pub const LLAMA_OPTIMISM_MAINNET_HOSTNAME: &str = "optimism.llamarpc.com";

thread_local! {
    pub static PROVIDERS: Vec<Provider> = vec![
        Provider {
            provider_id: 0,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{CLOUDFLARE_HOSTNAME}/v1/mainnet"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 1,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ANKR_HOSTNAME}/eth"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 2,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{PUBLICNODE_ETH_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 3,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{BLOCKPI_ETH_MAINNET_HOSTNAME}/v1/rpc/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 4,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            url_pattern: format!("https://{ETH_SEPOLIA_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 5,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            url_pattern: format!("https://{ANKR_HOSTNAME}/eth_sepolia"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 6,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            url_pattern: format!("https://{BLOCKPI_ETH_SEPOLIA_HOSTNAME}/v1/rpc/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 7,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            url_pattern: format!("https://{PUBLICNODE_ETH_SEPOLIA_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 8,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ALCHEMY_ETH_MAINNET_HOSTNAME}/v2/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 9,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            url_pattern: format!("https://{ALCHEMY_ETH_SEPOLIA_HOSTNAME}/v2/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 10,
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            url_pattern: format!("https://{ANKR_HOSTNAME}/arbitrum"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 11,
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            url_pattern: format!("https://{ALCHEMY_ARBITRUM_ONE_HOSTNAME}/v2"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 12,
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            url_pattern: format!("https://{BLOCKPI_ARBITRUM_ONE_HOSTNAME}/v1/rpc/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 13,
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            url_pattern: format!("https://{PUBLICNODE_ARBITRUM_ONE_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 14,
            chain_id: BASE_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ANKR_HOSTNAME}/base"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 15,
            chain_id: BASE_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ALCHEMY_BASE_MAINNET_HOSTNAME}/v2"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 16,
            chain_id: BASE_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{BLOCKPI_BASE_MAINNET_HOSTNAME}/v1/rpc/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 17,
            chain_id: BASE_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{PUBLICNODE_BASE_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 18,
            chain_id: OPTIMISM_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ANKR_HOSTNAME}/optimism"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 19,
            chain_id: OPTIMISM_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{ALCHEMY_OPT_MAINNET_HOSTNAME}/v2"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 20,
            chain_id: OPTIMISM_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{BLOCKPI_OPTIMISM_MAINNET_HOSTNAME}/v1/rpc/{{API_KEY}}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 21,
            chain_id: OPTIMISM_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{PUBLICNODE_OPTIMISM_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 22,
            chain_id: ETH_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{LLAMA_ETH_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 23,
            chain_id: ARBITRUM_ONE_CHAIN_ID,
            url_pattern: format!("https://{LLAMA_ARBITRUM_ONE_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 24,
            chain_id: BASE_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{LLAMA_BASE_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
        Provider {
            provider_id: 25,
            chain_id: OPTIMISM_MAINNET_CHAIN_ID,
            url_pattern: format!("https://{LLAMA_OPTIMISM_MAINNET_HOSTNAME}"),
            header_patterns: vec![],
        },
    ];

    pub static PROVIDER_MAP: HashMap<ProviderId, Provider> =
        PROVIDERS.with(|providers| providers.iter()
            .map(|provider| (provider.provider_id, provider.clone())).collect());

    pub static SERVICE_PROVIDER_MAP: HashMap<RpcService, ProviderId> = hashmap! {
        RpcService::EthMainnet(EthMainnetService::Cloudflare) => 0,
        RpcService::EthMainnet(EthMainnetService::Ankr) => 1,
        RpcService::EthMainnet(EthMainnetService::PublicNode) => 2,
        RpcService::EthMainnet(EthMainnetService::BlockPi) => 3,
        // RpcService::EthMainnet(EthSepoliaService::Sepolia) => 4,
        RpcService::EthSepolia(EthSepoliaService::Ankr) => 5,
        RpcService::EthSepolia(EthSepoliaService::BlockPi) => 6,
        RpcService::EthSepolia(EthSepoliaService::PublicNode) => 7,
        RpcService::EthMainnet(EthMainnetService::Alchemy) => 8,
        RpcService::EthSepolia(EthSepoliaService::Alchemy) => 9,
        RpcService::ArbitrumOne(L2MainnetService::Ankr) => 10,
        RpcService::ArbitrumOne(L2MainnetService::Alchemy) => 11,
        RpcService::ArbitrumOne(L2MainnetService::BlockPi) => 12,
        RpcService::ArbitrumOne(L2MainnetService::PublicNode) => 13,
        RpcService::BaseMainnet(L2MainnetService::Ankr) => 14,
        RpcService::BaseMainnet(L2MainnetService::Alchemy) => 15,
        RpcService::BaseMainnet(L2MainnetService::BlockPi) => 16,
        RpcService::BaseMainnet(L2MainnetService::PublicNode) => 17,
        RpcService::OptimismMainnet(L2MainnetService::Ankr) => 18,
        RpcService::OptimismMainnet(L2MainnetService::Alchemy) => 19,
        RpcService::OptimismMainnet(L2MainnetService::BlockPi) => 20,
        RpcService::OptimismMainnet(L2MainnetService::PublicNode) => 21,
        RpcService::EthMainnet(EthMainnetService::Llama) => 22,
        RpcService::ArbitrumOne(L2MainnetService::Llama) => 23,
        RpcService::BaseMainnet(L2MainnetService::Llama) => 24,
        RpcService::OptimismMainnet(L2MainnetService::Llama) => 25,
    };
}

pub fn find_provider(f: impl Fn(&Provider) -> bool) -> Option<Provider> {
    PROVIDERS.with(|providers| {
        for provider in providers {
            if f(provider) {
                return Some(provider.clone());
            }
        }
        None
    })
}

fn lookup_provider_for_service(service: &RpcService) -> Result<Provider, ProviderError> {
    let provider_id = SERVICE_PROVIDER_MAP.with(|map| {
        map.get(service)
            .copied()
            .ok_or(ProviderError::MissingRequiredProvider)
    })?;
    PROVIDER_MAP
        .with(|map| map.get(&provider_id).cloned())
        .ok_or(ProviderError::ProviderNotFound)
}

pub fn get_known_chain_id(service: &RpcService) -> Option<u64> {
    match service {
        RpcService::Chain(chain_id) => Some(*chain_id),
        RpcService::Provider(_) => None,
        RpcService::Custom(_) => None,
        RpcService::EthMainnet(_) => Some(ETH_MAINNET_CHAIN_ID),
        RpcService::EthSepolia(_) => Some(ETH_SEPOLIA_CHAIN_ID),
        RpcService::ArbitrumOne(_) => Some(ARBITRUM_ONE_CHAIN_ID),
        RpcService::BaseMainnet(_) => Some(BASE_MAINNET_CHAIN_ID),
        RpcService::OptimismMainnet(_) => Some(OPTIMISM_MAINNET_CHAIN_ID),
    }
}

pub fn resolve_rpc_service(service: RpcService) -> Result<ResolvedRpcService, ProviderError> {
    Ok(match service {
        RpcService::Chain(id) => ResolvedRpcService::Provider(
            find_provider(|p| p.chain_id == id).ok_or(ProviderError::ProviderNotFound)?,
        ),
        RpcService::Provider(id) => ResolvedRpcService::Provider({
            PROVIDER_MAP.with(|provider_map| {
                provider_map
                    .get(&id)
                    .cloned()
                    .ok_or(ProviderError::ProviderNotFound)
            })?
        }),
        RpcService::Custom(RpcApi { url, headers }) => {
            ResolvedRpcService::Api(RpcApi { url, headers })
        }
        RpcService::EthMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&RpcService::EthMainnet(service))?,
        ),
        RpcService::EthSepolia(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&RpcService::EthSepolia(service))?,
        ),
        RpcService::ArbitrumOne(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&RpcService::ArbitrumOne(service))?,
        ),
        RpcService::BaseMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&RpcService::BaseMainnet(service))?,
        ),
        RpcService::OptimismMainnet(service) => ResolvedRpcService::Provider(
            lookup_provider_for_service(&RpcService::OptimismMainnet(service))?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::{PROVIDERS, SERVICE_PROVIDER_MAP};

    #[test]
    fn test_no_duplicate_service_providers() {
        SERVICE_PROVIDER_MAP.with(|map| {
            assert_eq!(
                map.len(),
                map.keys().collect::<HashSet<_>>().len(),
                "Duplicate service in mapping"
            );
            assert_eq!(
                map.len(),
                map.values().collect::<HashSet<_>>().len(),
                "Duplicate provider in mapping"
            );
        })
    }

    #[test]
    fn test_service_provider_coverage() {
        PROVIDERS.with(|providers| {
            SERVICE_PROVIDER_MAP.with(|map| {
                let inverse_map: HashMap<_, _> = map.iter().map(|(k, v)| (v, k)).collect();
                for provider in providers {
                    assert!(
                        inverse_map.contains_key(&provider.provider_id),
                        "Missing service mapping for provider: {}",
                        provider.provider_id
                    );
                }
            })
        })
    }
}
