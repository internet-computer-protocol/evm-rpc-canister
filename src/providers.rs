use crate::*;

pub fn get_default_providers() -> Vec<RegisterProvider> {
    vec![
        RegisterProvider {
            chain_id: 1, // Ethereum mainnet
            hostname: "cloudflare-eth.com".to_string(),
            credential_path: "/v1/mainnet".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProvider {
            chain_id: 5, // Goerli testnet
            hostname: "ethereum-goerli.publicnode.com".to_string(),
            credential_path: "".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
        RegisterProvider {
            chain_id: 11155111, // Sepolia testnet
            hostname: "rpc.sepolia.org".to_string(),
            credential_path: "".to_string(),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        },
    ]
}

pub fn do_register_provider(caller: Principal, provider: RegisterProvider) -> u64 {
    validate_hostname(&provider.hostname);
    validate_credential_path(&provider.credential_path);
    let provider_id = METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        let id = metadata.next_provider_id;
        metadata.next_provider_id += 1;
        m.borrow_mut().set(metadata).unwrap();
        id
    });
    PROVIDERS.with(|p| {
        p.borrow_mut().insert(
            provider_id,
            Provider {
                provider_id,
                owner: caller,
                chain_id: provider.chain_id,
                hostname: provider.hostname,
                credential_path: provider.credential_path,
                cycles_per_call: provider.cycles_per_call,
                cycles_per_message_byte: provider.cycles_per_message_byte,
                cycles_owed: 0,
                primary: false,
            },
        )
    });
    provider_id
}

pub fn do_unregister_provider(caller: Principal, provider_id: u64) -> bool {
    PROVIDERS.with(|p| {
        let mut p = p.borrow_mut();
        if let Some(provider) = p.get(&provider_id) {
            if provider.owner == caller || is_authorized(&caller, Auth::Admin) {
                p.remove(&provider_id).is_some()
            } else {
                ic_cdk::trap("Not authorized");
            }
        } else {
            false
        }
    })
}

pub fn do_update_provider(caller: Principal, update: UpdateProvider) {
    PROVIDERS.with(|p| {
        let mut p = p.borrow_mut();
        match p.get(&update.provider_id) {
            Some(mut provider) => {
                if provider.owner != caller && !is_authorized(&caller, Auth::Admin) {
                    ic_cdk::trap("Provider owner != caller");
                }
                if let Some(hostname) = update.hostname {
                    validate_hostname(&hostname);
                    provider.hostname = hostname;
                }
                if let Some(path) = update.credential_path {
                    validate_credential_path(&path);
                    provider.credential_path = path;
                }
                if let Some(primary) = update.primary {
                    provider.primary = primary;
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
