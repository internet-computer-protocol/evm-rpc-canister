use cketh_common::{
    eth_rpc::ProviderError,
    eth_rpc_client::providers::{EthMainnetService, EthSepoliaService, RpcService},
    logs::INFO,
};
use ic_canister_log::log;

use crate::*;

pub const ANKR_HOSTNAME: &str = "rpc.ankr.com";
pub const ALCHEMY_ETH_MAINNET_HOSTNAME: &str = "eth-mainnet.g.alchemy.com";
pub const ALCHEMY_ETH_SEPOLIA_HOSTNAME: &str = "eth-sepolia.g.alchemy.com";
pub const CLOUDFLARE_HOSTNAME: &str = "cloudflare-eth.com";
pub const BLOCKPI_ETH_MAINNET_HOSTNAME: &str = "ethereum.blockpi.network";
pub const BLOCKPI_ETH_SEPOLIA_HOSTNAME: &str = "ethereum-sepolia.blockpi.network";
pub const PUBLICNODE_ETH_MAINNET_HOSTNAME: &str = "ethereum.publicnode.com";
pub const PUBLICNODE_ETH_SEPOLIA_HOSTNAME: &str = "ethereum-sepolia.publicnode.com";
pub const ETH_SEPOLIA_HOSTNAME: &str = "rpc.sepolia.org";

// Limited API credentials for local testing.
// Use `dfx canister call evm_rpc updateProvider ...` to pass your own keys.
pub const ALCHEMY_ETH_MAINNET_CREDENTIAL: &str = "/v2/zBxaSBUMfuH8XnA-uLIWeXfCx1T8ItkM";
pub const ALCHEMY_ETH_SEPOLIA_CREDENTIAL: &str = "/v2/Mbow19DWsfPXiTpdgvRu4HQq63iYycU-";
pub const BLOCKPI_ETH_MAINNET_CREDENTIAL: &str = "/v1/rpc/0edc81e20be23ddff051f61a97bb457ec7284a58";
pub const BLOCKPI_ETH_SEPOLIA_CREDENTIAL: &str = "/v1/rpc/1fe987fddded17db50862311720ff444991d4dab";

pub fn get_default_providers() -> Vec<RegisterProviderArgs> {
    vec![
        RegisterProviderArgs {
            chain_id: ETH_MAINNET_CHAIN_ID,
            hostname: CLOUDFLARE_HOSTNAME.to_string(),
            credential_path: "/v1/mainnet".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_MAINNET_CHAIN_ID,
            hostname: ANKR_HOSTNAME.to_string(),
            credential_path: "/eth".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_MAINNET_CHAIN_ID,
            hostname: PUBLICNODE_ETH_MAINNET_HOSTNAME.to_string(),
            credential_path: "".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_MAINNET_CHAIN_ID,
            hostname: BLOCKPI_ETH_MAINNET_HOSTNAME.to_string(),
            credential_path: BLOCKPI_ETH_MAINNET_CREDENTIAL.to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            hostname: ETH_SEPOLIA_HOSTNAME.to_string(),
            credential_path: "".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            hostname: ANKR_HOSTNAME.to_string(),
            credential_path: "/eth_sepolia".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            hostname: BLOCKPI_ETH_SEPOLIA_HOSTNAME.to_string(),
            credential_path: BLOCKPI_ETH_SEPOLIA_CREDENTIAL.to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            hostname: PUBLICNODE_ETH_SEPOLIA_HOSTNAME.to_string(),
            credential_path: "".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_MAINNET_CHAIN_ID,
            hostname: ALCHEMY_ETH_MAINNET_HOSTNAME.to_string(),
            credential_path: ALCHEMY_ETH_MAINNET_CREDENTIAL.to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProviderArgs {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            hostname: ALCHEMY_ETH_SEPOLIA_HOSTNAME.to_string(),
            credential_path: ALCHEMY_ETH_SEPOLIA_CREDENTIAL.to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
    ]
}

pub fn get_default_service_provider_hostnames() -> Vec<(RpcService, &'static str)> {
    vec![
        (
            RpcService::EthMainnet(EthMainnetService::Alchemy),
            ALCHEMY_ETH_MAINNET_HOSTNAME,
        ),
        (
            RpcService::EthMainnet(EthMainnetService::Ankr),
            ANKR_HOSTNAME,
        ),
        (
            RpcService::EthMainnet(EthMainnetService::BlockPi),
            BLOCKPI_ETH_MAINNET_HOSTNAME,
        ),
        (
            RpcService::EthMainnet(EthMainnetService::Cloudflare),
            CLOUDFLARE_HOSTNAME,
        ),
        (
            RpcService::EthMainnet(EthMainnetService::PublicNode),
            PUBLICNODE_ETH_MAINNET_HOSTNAME,
        ),
        (
            RpcService::EthSepolia(EthSepoliaService::Alchemy),
            ALCHEMY_ETH_SEPOLIA_HOSTNAME,
        ),
        (
            RpcService::EthSepolia(EthSepoliaService::Ankr),
            ANKR_HOSTNAME,
        ),
        (
            RpcService::EthSepolia(EthSepoliaService::BlockPi),
            BLOCKPI_ETH_SEPOLIA_HOSTNAME,
        ),
        (
            RpcService::EthSepolia(EthSepoliaService::PublicNode),
            PUBLICNODE_ETH_SEPOLIA_HOSTNAME,
        ),
    ]
}

pub fn find_provider(f: impl Fn(&Provider) -> bool) -> Option<Provider> {
    PROVIDERS.with(|providers| {
        let providers = providers.borrow();
        Some(
            providers
                .iter()
                .find(|(_, p)| p.primary && f(p))
                .or_else(|| providers.iter().find(|(_, p)| f(p)))?
                .1,
        )
    })
}

pub fn get_provider_for_service(service: &RpcService) -> Result<Provider, ProviderError> {
    let provider_id = SERVICE_PROVIDER_MAP.with(|map| {
        map.borrow()
            .get(&StorableRpcService::new(service))
            .ok_or(ProviderError::MissingRequiredProvider)
    })?;
    PROVIDERS
        .with(|providers| providers.borrow().get(&provider_id))
        .ok_or(ProviderError::ProviderNotFound)
}

pub fn get_chain_id(service: &RpcService) -> u64 {
    match service {
        RpcService::EthMainnet(_) => ETH_MAINNET_CHAIN_ID,
        RpcService::EthSepolia(_) => ETH_SEPOLIA_CHAIN_ID,
    }
}

pub fn do_register_provider(caller: Principal, args: RegisterProviderArgs) -> u64 {
    validate_hostname(&args.hostname).unwrap();
    validate_credential_path(&args.credential_path).unwrap();
    let provider_id = METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        let id = metadata.next_provider_id;
        metadata.next_provider_id += 1;
        m.borrow_mut().set(metadata).unwrap();
        id
    });
    do_deauthorize(caller, Auth::RegisterProvider);
    log!(INFO, "[{}] Registering provider: {:?}", caller, provider_id);
    PROVIDERS.with(|providers| {
        providers.borrow_mut().insert(
            provider_id,
            Provider {
                provider_id,
                owner: caller,
                chain_id: args.chain_id,
                hostname: args.hostname,
                credential_path: args.credential_path,
                credential_headers: args.credential_headers.unwrap_or_default(),
                cycles_per_call: args.cycles_per_call,
                cycles_per_message_byte: args.cycles_per_message_byte,
                cycles_owed: 0,
                primary: false,
            },
        )
    });
    provider_id
}

pub fn do_unregister_provider(caller: Principal, is_controller: bool, provider_id: u64) -> bool {
    PROVIDERS.with(|providers| {
        let mut providers = providers.borrow_mut();
        if let Some(provider) = providers.get(&provider_id) {
            if !(provider.owner == caller || is_controller) {
                ic_cdk::trap("You are not authorized: check provider owner");
            } else {
                log!(
                    INFO,
                    "[{}] Unregistering provider: {:?}",
                    caller,
                    provider_id
                );
                providers.remove(&provider_id).is_some()
            }
        } else {
            false
        }
    })
}

/// Changes provider details. The caller must be the owner of the provider.
pub fn do_update_provider(caller: Principal, is_controller: bool, args: UpdateProviderArgs) {
    PROVIDERS.with(|providers| {
        let mut providers = providers.borrow_mut();
        match providers.get(&args.provider_id) {
            Some(mut provider) => {
                if !(provider.owner == caller || is_controller) {
                    ic_cdk::trap("You are not authorized: check provider owner");
                } else {
                    log!(INFO, "[{}] Updating provider: {}", caller, args.provider_id);
                    if let Some(hostname) = args.hostname {
                        validate_hostname(&hostname).unwrap();
                        provider.hostname = hostname;
                    }
                    if let Some(path) = args.credential_path {
                        validate_credential_path(&path).unwrap();
                        provider.credential_path = path;
                    }
                    if let Some(headers) = args.credential_headers {
                        validate_credential_headers(&headers).unwrap();
                        provider.credential_headers = headers;
                    }
                    if let Some(cycles_per_call) = args.cycles_per_call {
                        provider.cycles_per_call = cycles_per_call;
                    }
                    if let Some(cycles_per_message_byte) = args.cycles_per_message_byte {
                        provider.cycles_per_message_byte = cycles_per_message_byte;
                    }
                    providers.insert(args.provider_id, provider);
                }
            }
            None => ic_cdk::trap("Provider not found"),
        }
    });
}

/// Changes administrative details for a provider. The caller must have the `Auth::Manage` permission.
pub fn do_manage_provider(args: ManageProviderArgs) {
    PROVIDERS.with(|providers| {
        let mut providers = providers.borrow_mut();
        match providers.get(&args.provider_id) {
            Some(mut provider) => {
                if let Some(primary) = args.primary {
                    provider.primary = primary;
                }
                if let Some(service) = args.service {
                    set_service_provider(&service, &provider);
                }
                providers.insert(args.provider_id, provider);
            }
            None => ic_cdk::trap("Provider not found"),
        }
    })
}

pub fn set_service_provider(service: &RpcService, provider: &Provider) {
    log!(
        INFO,
        "Changing service {:?} to use provider: {}",
        service,
        provider.provider_id
    );
    let chain_id = get_chain_id(service);
    if chain_id != provider.chain_id {
        ic_cdk::trap(&format!(
            "Mismatch between service and provider chain ids ({} != {})",
            chain_id, provider.chain_id
        ))
    }
    SERVICE_PROVIDER_MAP.with(|mappings| {
        mappings
            .borrow_mut()
            .insert(StorableRpcService::new(service), provider.provider_id);
    });
}
