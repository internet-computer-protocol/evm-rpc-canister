use crate::*;

pub fn get_default_providers() -> Vec<RegisterProvider> {
    vec![
        RegisterProvider {
            chain_id: 0x1, // Ethereum mainnet
            base_url: "https://cloudflare-eth.com".to_string(),
            credential_path: "/v1/mainnet".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProvider {
            chain_id: 0x5, // Goerli testnet
            base_url: "https://ethereum-goerli.publicnode.com".to_string(),
            credential_path: "".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProvider {
            chain_id: 0xaa36a7, // Sepolia testnet
            base_url: "https://rpc.sepolia.org".to_string(),
            credential_path: "".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
    ]
}

pub fn do_register_provider(provider: RegisterProvider) -> u64 {
    let parsed_url = url::Url::parse(&provider.base_url).expect("unable to parse service_url");
    let host = parsed_url.host_str().expect("service_url host missing");
    validate_base_url(host);
    validate_credential_path(&provider.credential_path);
    let provider_id = METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.next_provider_id += 1;
        m.borrow_mut().set(metadata.clone()).unwrap();
        metadata.next_provider_id - 1
    });
    PROVIDERS.with(|p| {
        p.borrow_mut().insert(
            provider_id,
            Provider {
                provider_id,
                owner: ic_cdk::caller(),
                chain_id: provider.chain_id,
                base_url: provider.base_url,
                credential_path: provider.credential_path,
                cycles_per_call: provider.cycles_per_call,
                cycles_per_message_byte: provider.cycles_per_message_byte,
                cycles_owed: 0,
                active: true,
            },
        )
    });
    provider_id
}

pub fn do_unregister_provider(provider_id: u64) -> bool {
    PROVIDERS.with(|p| {
        if let Some(provider) = p.borrow().get(&provider_id) {
            if provider.owner == ic_cdk::caller() || is_authorized(Auth::Admin) {
                return p.borrow_mut().remove(&provider_id).is_some();
            } else {
                ic_cdk::trap("Not authorized");
            }
        }
        false
    })
}

pub fn do_update_provider(update: UpdateProvider) {
    PROVIDERS.with(|p| {
        let mut p = p.borrow_mut();
        match p.get(&update.provider_id) {
            Some(mut provider) => {
                if provider.owner != ic_cdk::caller() && !is_authorized(Auth::Admin) {
                    ic_cdk::trap("Provider owner != caller");
                }
                if let Some(url) = update.base_url {
                    validate_base_url(&url);
                    provider.base_url = url;
                }
                if let Some(path) = update.credential_path {
                    validate_credential_path(&path);
                    provider.credential_path = path;
                }
                if let Some(active) = update.active {
                    provider.active = active;
                }
                if let Some(cycles_per_call) = update.cycles_per_call {
                    provider.cycles_per_call = cycles_per_call;
                }
                if let Some(cycles_per_message_byte) = update.cycles_per_message_byte {
                    provider.cycles_per_message_byte = cycles_per_message_byte;
                }
                p.insert(update.provider_id, provider);
            }
            None => ic_cdk::trap("Provider not found"),
        }
    });
}
