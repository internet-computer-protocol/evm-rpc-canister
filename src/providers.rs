use std::collections::HashMap;

use cketh_common::{
    eth_rpc::ProviderError,
    eth_rpc_client::providers::{
        EthMainnetService, EthSepoliaService, L2MainnetService, RpcApi, RpcService,
    },
};

use crate::{
    constants::{
        ARBITRUM_ONE_CHAIN_ID, BASE_MAINNET_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        OPTIMISM_MAINNET_CHAIN_ID,
    },
    types::{ConstHeader, Provider, ProviderId, ResolvedRpcService},
};

const ALCHEMY_HEADERS: &[ConstHeader] = &[ConstHeader {
    name: "Authorization",
    value: "Bearer {API_KEY}",
}];

pub const PROVIDERS: &[Provider] = &[
    Provider {
        provider_id: 0,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: Some("https://cloudflare-eth.com/v1/mainnet"),
        url_pattern: "https://cloudflare-eth.com/v1/mainnet/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::EthMainnet(EthMainnetService::Cloudflare)),
    },
    Provider {
        provider_id: 1,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://rpc.ankr.com/eth/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::EthMainnet(EthMainnetService::Ankr)),
    },
    Provider {
        provider_id: 2,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: Some("https://ethereum-rpc.publicnode.com"),
        url_pattern: "https://ethereum-rpc.publicnode.com",
        header_patterns: &[],
        alias: Some(RpcService::EthMainnet(EthMainnetService::PublicNode)),
    },
    Provider {
        provider_id: 3,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://ethereum.blockpi.network/v1/rpc/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::EthMainnet(EthMainnetService::BlockPi)),
    },
    Provider {
        provider_id: 4,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        public_url: Some("https://rpc.sepolia.org"),
        url_pattern: "https://rpc.sepolia.org",
        header_patterns: &[],
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Sepolia)),
    },
    Provider {
        provider_id: 5,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        public_url: None,
        url_pattern: "https://rpc.ankr.com/eth_sepolia/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Ankr)),
    },
    Provider {
        provider_id: 6,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        public_url: None,
        url_pattern: "https://ethereum-sepolia.blockpi.network/v1/rpc/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::EthSepolia(EthSepoliaService::BlockPi)),
    },
    Provider {
        provider_id: 7,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        public_url: Some("https://ethereum-sepolia-rpc.publicnode.com"),
        url_pattern: "https://ethereum-sepolia-rpc.publicnode.com",
        header_patterns: &[],
        alias: Some(RpcService::EthSepolia(EthSepoliaService::PublicNode)),
    },
    Provider {
        provider_id: 8,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://eth-mainnet.g.alchemy.com/v2",
        header_patterns: ALCHEMY_HEADERS,
        alias: Some(RpcService::EthMainnet(EthMainnetService::Alchemy)),
    },
    Provider {
        provider_id: 9,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        public_url: None,
        url_pattern: "https://eth-sepolia.g.alchemy.com/v2",
        header_patterns: ALCHEMY_HEADERS,
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Alchemy)),
    },
    Provider {
        provider_id: 10,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        public_url: None,
        url_pattern: "https://rpc.ankr.com/arbitrum/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 11,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        public_url: None,
        url_pattern: "https://arb-mainnet.g.alchemy.com/v2",
        header_patterns: ALCHEMY_HEADERS,
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 12,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        public_url: None,
        url_pattern: "https://arbitrum.blockpi.network/v1/rpc/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 13,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        public_url: Some("https://arbitrum-one-rpc.publicnode.com"),
        url_pattern: "https://arbitrum-one-rpc.publicnode.com",
        header_patterns: &[],
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 14,
        chain_id: BASE_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://rpc.ankr.com/base/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 15,
        chain_id: BASE_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://base-mainnet.g.alchemy.com/v2",
        header_patterns: ALCHEMY_HEADERS,
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 16,
        chain_id: BASE_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://base.blockpi.network/v1/rpc/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::BaseMainnet(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 17,
        chain_id: BASE_MAINNET_CHAIN_ID,
        public_url: Some("https://base-rpc.publicnode.com"),
        url_pattern: "https://base-rpc.publicnode.com",
        header_patterns: &[],
        alias: Some(RpcService::BaseMainnet(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 18,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://rpc.ankr.com/optimism/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 19,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://opt-mainnet.g.alchemy.com/v2",
        header_patterns: ALCHEMY_HEADERS,
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 20,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        public_url: None,
        url_pattern: "https://optimism.blockpi.network/v1/rpc/{API_KEY}",
        header_patterns: &[],
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 21,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        public_url: Some("https://optimism-rpc.publicnode.com"),
        url_pattern: "https://optimism-rpc.publicnode.com",
        header_patterns: &[],
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 22,
        chain_id: ETH_MAINNET_CHAIN_ID,
        public_url: Some("https://eth.llamarpc.com"),
        url_pattern: "https://eth.llamarpc.com",
        header_patterns: &[],
        alias: Some(RpcService::EthMainnet(EthMainnetService::Llama)),
    },
    Provider {
        provider_id: 23,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        public_url: Some("https://arbitrum.llamarpc.com"),
        url_pattern: "https://arbitrum.llamarpc.com",
        header_patterns: &[],
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 24,
        chain_id: BASE_MAINNET_CHAIN_ID,
        public_url: Some("https://base.llamarpc.com"),
        url_pattern: "https://base.llamarpc.com",
        header_patterns: &[],
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 25,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        public_url: Some("https://optimism.llamarpc.com"),
        url_pattern: "https://optimism.llamarpc.com",
        header_patterns: &[],
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::Llama)),
    },
];

thread_local! {
    pub static PROVIDER_MAP: HashMap<ProviderId, Provider> =
        PROVIDERS.iter()
            .map(|provider| (provider.provider_id, provider.clone())).collect();

    pub static SERVICE_PROVIDER_MAP: HashMap<RpcService, ProviderId> =
        PROVIDERS.iter()
            .filter_map(|provider| Some((provider.alias.clone()?, provider.provider_id)))
            .collect();
}

pub fn find_provider(f: impl Fn(&Provider) -> bool) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|&provider| f(provider))
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
            find_provider(|p| p.chain_id == id)
                .ok_or(ProviderError::ProviderNotFound)?
                .clone(),
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
mod test {
    use std::collections::{HashMap, HashSet};

    use crate::{constants::CONTENT_TYPE_HEADER, validate::validate_url_pattern};

    use super::{PROVIDERS, SERVICE_PROVIDER_MAP};

    #[test]
    fn test_valid_rpc_providers() {
        for provider in PROVIDERS {
            assert_eq!(validate_url_pattern(provider.url_pattern), Ok(()));
        }
    }

    #[test]
    pub fn test_no_content_type_in_rpc_provider_headers() {
        assert!(PROVIDERS.iter().all(|provider| provider
            .header_patterns
            .iter()
            .all(|header| header.name.to_lowercase() != CONTENT_TYPE_HEADER.to_lowercase())));
    }

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
        SERVICE_PROVIDER_MAP.with(|map| {
            let inverse_map: HashMap<_, _> = map.iter().map(|(k, v)| (v, k)).collect();
            for provider in PROVIDERS {
                assert!(
                    inverse_map.contains_key(&provider.provider_id),
                    "Missing service mapping for provider with ID: {}",
                    provider.provider_id
                );
            }
        })
    }
}
