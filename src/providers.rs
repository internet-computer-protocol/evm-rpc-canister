use evm_rpc_types::{
    EthMainnetService, EthSepoliaService, L2MainnetService, ProviderError, RpcApi, RpcService,
};
use std::collections::HashMap;

use crate::{
    constants::{
        ARBITRUM_ONE_CHAIN_ID, BASE_MAINNET_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        OPTIMISM_MAINNET_CHAIN_ID,
    },
    types::{Provider, ProviderId, ResolvedRpcService, RpcAccess, RpcAuth},
};

pub const PROVIDERS: &[Provider] = &[
    Provider {
        provider_id: 0,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://cloudflare-eth.com/v1/mainnet",
            },
            public_url: Some("https://cloudflare-eth.com/v1/mainnet"),
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::Cloudflare)),
    },
    Provider {
        provider_id: 1,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/eth/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/eth"),
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::Ankr)),
    },
    Provider {
        provider_id: 2,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://ethereum-rpc.publicnode.com",
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::PublicNode)),
    },
    Provider {
        provider_id: 3,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://ethereum.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://ethereum.blockpi.network/v1/rpc/public"),
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::BlockPi)),
    },
    Provider {
        provider_id: 4,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://rpc.sepolia.org",
        },
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Sepolia)),
    },
    Provider {
        provider_id: 5,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/eth_sepolia/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/eth_sepolia"),
        },
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Ankr)),
    },
    Provider {
        provider_id: 6,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://ethereum-sepolia.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://ethereum-sepolia.blockpi.network/v1/rpc/public"),
        },
        alias: Some(RpcService::EthSepolia(EthSepoliaService::BlockPi)),
    },
    Provider {
        provider_id: 7,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://ethereum-sepolia-rpc.publicnode.com",
        },
        alias: Some(RpcService::EthSepolia(EthSepoliaService::PublicNode)),
    },
    Provider {
        provider_id: 8,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://eth-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://eth-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::Alchemy)),
    },
    Provider {
        provider_id: 9,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://eth-sepolia.g.alchemy.com/v2",
            },
            public_url: Some("https://eth-sepolia.g.alchemy.com/v2/demo"),
        },
        alias: Some(RpcService::EthSepolia(EthSepoliaService::Alchemy)),
    },
    Provider {
        provider_id: 10,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/arbitrum/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/arbitrum"),
        },
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 11,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://arb-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://arb-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 12,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://arbitrum.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://arbitrum.blockpi.network/v1/rpc/public"),
        },
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 13,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://arbitrum-one-rpc.publicnode.com",
        },
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 14,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/base/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/base"),
        },
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 15,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://base-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://base-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 16,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://base.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://base.blockpi.network/v1/rpc/public"),
        },
        alias: Some(RpcService::BaseMainnet(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 17,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://base-rpc.publicnode.com",
        },
        alias: Some(RpcService::BaseMainnet(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 18,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://rpc.ankr.com/optimism/{API_KEY}",
            },
            public_url: Some("https://rpc.ankr.com/optimism"),
        },
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::Ankr)),
    },
    Provider {
        provider_id: 19,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::BearerToken {
                url: "https://opt-mainnet.g.alchemy.com/v2",
            },
            public_url: Some("https://opt-mainnet.g.alchemy.com/v2/demo"),
        },
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::Alchemy)),
    },
    Provider {
        provider_id: 20,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Authenticated {
            auth: RpcAuth::UrlParameter {
                url_pattern: "https://optimism.blockpi.network/v1/rpc/{API_KEY}",
            },
            public_url: Some("https://optimism.blockpi.network/v1/rpc/public"),
        },
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::BlockPi)),
    },
    Provider {
        provider_id: 21,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://optimism-rpc.publicnode.com",
        },
        alias: Some(RpcService::OptimismMainnet(L2MainnetService::PublicNode)),
    },
    Provider {
        provider_id: 22,
        chain_id: ETH_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://eth.llamarpc.com",
        },
        alias: Some(RpcService::EthMainnet(EthMainnetService::Llama)),
    },
    Provider {
        provider_id: 23,
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://arbitrum.llamarpc.com",
        },
        alias: Some(RpcService::ArbitrumOne(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 24,
        chain_id: BASE_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://base.llamarpc.com",
        },
        alias: Some(RpcService::BaseMainnet(L2MainnetService::Llama)),
    },
    Provider {
        provider_id: 25,
        chain_id: OPTIMISM_MAINNET_CHAIN_ID,
        access: RpcAccess::Unauthenticated {
            public_url: "https://optimism.llamarpc.com",
        },
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

    use crate::{
        constants::API_KEY_REPLACE_STRING,
        types::{Provider, RpcAccess, RpcAuth},
    };

    use super::{PROVIDERS, SERVICE_PROVIDER_MAP};

    #[test]
    fn test_provider_id_sequence() {
        for (i, provider) in PROVIDERS.iter().enumerate() {
            assert_eq!(provider.provider_id, i as u64);
        }
    }

    #[test]
    fn test_rpc_provider_url_patterns() {
        for provider in PROVIDERS {
            fn assert_not_url_pattern(url: &str, provider: &Provider) {
                assert!(
                    !url.contains(API_KEY_REPLACE_STRING),
                    "Unexpected API key in URL for provider: {}",
                    provider.provider_id
                )
            }
            fn assert_url_pattern(url: &str, provider: &Provider) {
                assert!(
                    url.contains(API_KEY_REPLACE_STRING),
                    "Missing API key in URL pattern for provider: {}",
                    provider.provider_id
                )
            }
            match &provider.access {
                RpcAccess::Authenticated { auth, public_url } => {
                    match auth {
                        RpcAuth::BearerToken { url } => assert_not_url_pattern(url, provider),
                        RpcAuth::UrlParameter { url_pattern } => {
                            assert_url_pattern(url_pattern, provider)
                        }
                    }
                    if let Some(public_url) = public_url {
                        assert_not_url_pattern(public_url, provider);
                    }
                }
                RpcAccess::Unauthenticated { public_url } => {
                    assert_not_url_pattern(public_url, provider);
                }
            }
        }
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
