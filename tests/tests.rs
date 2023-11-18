use std::rc::Rc;

use candid::{CandidType, Decode, Encode, Nat};
use evm_rpc::*;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::BoundedVec;
use ic_state_machine_tests::{CanisterSettingsArgs, StateMachine, StateMachineBuilder, WasmResult};
use ic_test_utilities_load_wasm::load_wasm;
use serde::de::DeserializeOwned;

const DEFAULT_CALLER_TEST_ID: u64 = 10352385;
const DEFAULT_CONTROLLER_TEST_ID: u64 = 10352386;

fn evm_rpc_wasm() -> Vec<u8> {
    load_wasm(std::env::var("CARGO_MANIFEST_DIR").unwrap(), "evm_rpc", &[])
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        result => {
            panic!("Expected a successful reply, got {}", result)
        }
    }
}

#[derive(Clone)]
pub struct EvmRpcSetup {
    pub env: Rc<StateMachine>,
    pub caller: PrincipalId,
    pub controller: PrincipalId,
    pub evm_rpc_id: CanisterId,
}

impl Default for EvmRpcSetup {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmRpcSetup {
    pub fn new() -> Self {
        let env = Rc::new(
            StateMachineBuilder::new()
                .with_default_canister_range()
                .build(),
        );

        let controller = PrincipalId::new_user_test_id(DEFAULT_CONTROLLER_TEST_ID);
        let evm_rpc_id = env.create_canister(Some({
            let mut args: CanisterSettingsArgs = Default::default();
            args.controllers = Some(BoundedVec::new(vec![controller]));
            args
        }));
        env.install_existing_canister(evm_rpc_id, evm_rpc_wasm(), Encode!(&()).unwrap())
            .unwrap();

        let caller = PrincipalId::new_user_test_id(DEFAULT_CALLER_TEST_ID);

        Self {
            env,
            caller,
            controller,
            evm_rpc_id,
        }
    }

    pub fn as_controller(&self) -> Self {
        let mut setup = self.clone();
        setup.caller = self.controller;
        setup
    }

    pub fn as_anonymous(&self) -> Self {
        let mut setup = self.clone();
        setup.caller = PrincipalId::new_anonymous();
        setup
    }

    pub fn as_caller(&self, id: PrincipalId) -> Self {
        let mut setup = self.clone();
        setup.caller = id;
        setup
    }

    fn call_update<R: CandidType + DeserializeOwned>(&self, method: &str, input: Vec<u8>) -> R {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(self.caller, self.evm_rpc_id, method, input,)
                    .unwrap_or_else(|err| panic!(
                        "error during update call to `{}()`: {}",
                        method, err
                    ))
            ),
            R
        )
        .unwrap()
    }

    fn call_query<R: CandidType + DeserializeOwned>(&self, method: &str, input: Vec<u8>) -> R {
        Decode!(
            &assert_reply(
                self.env
                    .query_as(self.caller, self.evm_rpc_id, method, input,)
                    .unwrap_or_else(|err| panic!(
                        "error during query call to `{}()`: {}",
                        method, err
                    ))
            ),
            R
        )
        .unwrap()
    }

    pub fn authorize(&self, principal: &PrincipalId, auth: Auth) {
        self.call_update("authorize", Encode!(&principal.0, &auth).unwrap())
    }

    pub fn deauthorize(&self, principal: &PrincipalId, auth: Auth) {
        self.call_update("deauthorize", Encode!(&principal.0, &auth).unwrap())
    }

    pub fn get_providers(&self) -> Vec<ProviderView> {
        self.call_update("get_providers", Encode!().unwrap())
    }

    pub fn register_provider(&self, args: RegisterProviderArgs) -> u64 {
        self.call_update("register_provider", Encode!(&args).unwrap())
    }

    pub fn authorize_caller(self, auth: Auth) -> Self {
        self.as_controller().authorize(&self.caller, auth);
        self
    }

    pub fn deauthorize_caller(self, auth: Auth) -> Self {
        self.as_controller().deauthorize(&self.caller, auth);
        self
    }

    pub fn request_cost(
        &self,
        source: Source,
        json_rpc_payload: &str,
        max_response_bytes: u64,
    ) -> Nat {
        self.call_query(
            "request_cost",
            Encode!(&source, &json_rpc_payload, &max_response_bytes).unwrap(),
        )
    }
}

#[test]
fn test_register_provider() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::RegisterProvider);

    let a_id = setup.register_provider(RegisterProviderArgs {
        chain_id: 1,
        hostname: "cloudflare-eth.com".to_string(),
        credential_path: "".to_string(),
        credential_headers: None,
        cycles_per_call: 0,
        cycles_per_message_byte: 0,
    });
    let b_id = setup.register_provider(RegisterProviderArgs {
        chain_id: 5,
        hostname: "ethereum.publicnode.com".to_string(),
        credential_path: "".to_string(),
        credential_headers: None,
        cycles_per_call: 0,
        cycles_per_message_byte: 0,
    });
    assert_eq!(a_id + 1, b_id);
    let providers = setup.get_providers();
    assert_eq!(
        providers[providers.len() - 2..],
        vec![
            ProviderView {
                provider_id: 3,
                owner: setup.caller.0,
                chain_id: 1,
                hostname: "cloudflare-eth.com".to_string(),
                cycles_per_call: 0,
                cycles_per_message_byte: 0,
                primary: false,
            },
            ProviderView {
                provider_id: 4,
                owner: setup.caller.0,
                chain_id: 5,
                hostname: "ethereum.publicnode.com".to_string(),
                cycles_per_call: 0,
                cycles_per_message_byte: 0,
                primary: false,
            }
        ]
    )
}
