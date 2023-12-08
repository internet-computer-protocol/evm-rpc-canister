mod mock;

use std::{marker::PhantomData, rc::Rc, str::FromStr, time::Duration};

use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Nat};
use cketh_common::{
    eth_rpc::{Block, LogEntry},
    numeric::{BlockNumber, Wei},
};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse as OutCallHttpResponse,
    TransformArgs, TransformContext, TransformFunc,
};
use ic_ic00_types::CanisterSettingsArgsBuilder;
use ic_state_machine_tests::{
    CanisterHttpResponsePayload, Cycles, IngressState, IngressStatus, MessageId, PayloadBuilder,
    StateMachine, StateMachineBuilder, WasmResult,
};
use ic_test_utilities_load_wasm::load_wasm;
use serde::de::DeserializeOwned;

use evm_rpc::*;
use mock::*;

const DEFAULT_CALLER_TEST_ID: u64 = 10352385;
const DEFAULT_CONTROLLER_TEST_ID: u64 = 10352386;

const INITIAL_CYCLES: u128 = 100_000_000_000_000_000;

const MAX_TICKS: usize = 10;

const MOCK_REQUEST_URL: &str = "https://cloudflare-eth.com";
const MOCK_REQUEST_PAYLOAD: &str = r#"{"id":1,"jsonrpc":"2.0","method":"eth_gasPrice"}"#;
const MOCK_REQUEST_RESPONSE: &str = r#"{"id":1,"jsonrpc":"2.0","result":"0x00112233"}"#;
const MOCK_REQUEST_RESPONSE_BYTES: u64 = 1000;

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
    pub canister_id: CanisterId,
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
        let canister_id = env.create_canister_with_cycles(
            None,
            Cycles::new(INITIAL_CYCLES),
            Some(
                CanisterSettingsArgsBuilder::default()
                    .with_controller(controller)
                    .build(),
            ),
        );
        env.install_existing_canister(canister_id, evm_rpc_wasm(), Encode!(&()).unwrap())
            .unwrap();

        let caller = PrincipalId::new_user_test_id(DEFAULT_CALLER_TEST_ID);

        Self {
            env,
            caller,
            controller,
            canister_id,
        }
    }

    /// Shorthand for deriving an `EvmRpcSetup` with the caller as the canister controller.
    pub fn as_controller(mut self) -> Self {
        self.caller = self.controller;
        self
    }

    /// Shorthand for deriving an `EvmRpcSetup` with an anonymous caller.
    pub fn as_anonymous(mut self) -> Self {
        self.caller = PrincipalId::new_anonymous();
        self
    }

    /// Shorthand for deriving an `EvmRpcSetup` with an arbitrary caller.
    pub fn as_caller(mut self, id: PrincipalId) -> Self {
        self.caller = id;
        self
    }

    fn call_update<R: CandidType + DeserializeOwned>(
        &self,
        method: &str,
        input: Vec<u8>,
    ) -> CallFlow<R> {
        CallFlow::from_update(self.clone(), method, input)
    }

    fn call_query<R: CandidType + DeserializeOwned>(&self, method: &str, input: Vec<u8>) -> R {
        let candid = &assert_reply(
            self.env
                .query_as(self.caller, self.canister_id, method, input)
                .unwrap_or_else(|err| panic!("error during query call to `{}()`: {}", method, err)),
        );
        Decode!(candid, R).expect("error while decoding Candid response from query call")
    }

    pub fn tick_until_http_request(&self) {
        for _ in 0..MAX_TICKS {
            if !self.env.canister_http_request_contexts().is_empty() {
                break;
            }
            self.env.tick();
            self.env.advance_time(Duration::from_nanos(1));
        }
    }

    pub fn authorize(&self, principal: &PrincipalId, auth: Auth) -> CallFlow<()> {
        self.call_update("authorize", Encode!(&principal.0, &auth).unwrap())
    }

    pub fn deauthorize(&self, principal: &PrincipalId, auth: Auth) -> CallFlow<()> {
        self.call_update("deauthorize", Encode!(&principal.0, &auth).unwrap())
    }

    pub fn get_providers(&self) -> Vec<ProviderView> {
        self.call_query("get_providers", Encode!().unwrap())
    }

    pub fn register_provider(&self, args: RegisterProviderArgs) -> CallFlow<u64> {
        self.call_update("register_provider", Encode!(&args).unwrap())
    }

    pub fn authorize_caller(self, auth: Auth) -> Self {
        self.clone()
            .as_controller()
            .authorize(&self.caller, auth)
            .wait();
        self
    }

    pub fn deauthorize_caller(self, auth: Auth) -> Self {
        self.clone()
            .as_controller()
            .deauthorize(&self.caller, auth)
            .wait();
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

    pub fn request(
        &self,
        source: Source,
        json_rpc_payload: &str,
        max_response_bytes: u64,
    ) -> CallFlow<RpcResult<String>> {
        self.call_update(
            "request",
            Encode!(&source, &json_rpc_payload, &max_response_bytes).unwrap(),
        )
    }

    pub fn eth_get_logs(
        &self,
        source: CandidRpcSource,
        args: candid_types::GetLogsArgs,
    ) -> CallFlow<RpcResult<Vec<LogEntry>>> {
        self.call_update("eth_get_logs", Encode!(&source, &args).unwrap())
    }

    pub fn eth_get_block_by_number(
        &self,
        source: CandidRpcSource,
        block: candid_types::BlockSpec,
    ) -> CallFlow<RpcResult<Block>> {
        self.call_update("eth_get_block_by_number", Encode!(&source, &block).unwrap())
    }

    pub fn eth_get_transaction_receipt(
        &self,
        source: CandidRpcSource,
        address: &str,
    ) -> CallFlow<RpcResult<Option<candid_types::TransactionReceipt>>> {
        self.call_update(
            "eth_get_transaction_receipt",
            Encode!(&source, &address).unwrap(),
        )
    }

    pub fn eth_get_transaction_count(
        &self,
        source: CandidRpcSource,
        address: &str,
    ) -> CallFlow<RpcResult<Nat>> {
        self.call_update(
            "eth_get_transaction_count",
            Encode!(&source, &address).unwrap(),
        )
    }
}

pub struct CallFlow<R> {
    setup: EvmRpcSetup,
    method: String,
    message_id: MessageId,
    phantom: PhantomData<R>,
}

impl<R: CandidType + DeserializeOwned> CallFlow<R> {
    pub fn from_update(setup: EvmRpcSetup, method: &str, input: Vec<u8>) -> Self {
        let message_id = setup
            .env
            .send_ingress(setup.caller, setup.canister_id, method, input);
        CallFlow::new(setup, method, message_id)
    }

    pub fn new(setup: EvmRpcSetup, method: impl ToString, message_id: MessageId) -> Self {
        Self {
            setup,
            method: method.to_string(),
            message_id,
            phantom: Default::default(),
        }
    }

    pub fn mock_http(self, mock: impl Into<MockOutcall>) -> Self {
        let mock = mock.into();
        assert_eq!(self.setup.env.canister_http_request_contexts().len(), 0);
        self.setup.tick_until_http_request();
        match self.setup.env.ingress_status(&self.message_id) {
            IngressStatus::Known { state, .. } if state != IngressState::Processing => return self,
            _ => (),
        }
        let contexts = self.setup.env.canister_http_request_contexts();
        let (id, context) = contexts.first_key_value().expect("no pending HTTP request");

        mock.assert_matches(&CanisterHttpRequestArgument {
            url: context.url.clone(),
            max_response_bytes: context.max_response_bytes.map(|n| n.get()),
            // Convert HTTP method type by name
            method: serde_json::from_str(
                &serde_json::to_string(&context.http_method)
                    .unwrap()
                    .to_lowercase(),
            )
            .unwrap(),
            headers: context
                .headers
                .iter()
                .map(|h| HttpHeader {
                    name: h.name.clone(),
                    value: h.value.clone(),
                })
                .collect(),
            body: context.body.clone(),
            transform: context.transform.clone().map(|t| TransformContext {
                context: t.context,
                function: TransformFunc::new(self.setup.canister_id.get().0, t.method_name),
            }),
        });
        let mut response = OutCallHttpResponse {
            status: mock.response.status,
            headers: mock.response.headers,
            body: mock.response.body,
        };
        if let Some(transform) = &context.transform {
            let transform_args = TransformArgs {
                response,
                context: transform.context.to_vec(),
            };
            response = Decode!(
                &assert_reply(
                    self.setup
                        .env
                        .execute_ingress(
                            self.setup.canister_id,
                            transform.method_name.clone(),
                            Encode!(&transform_args).unwrap(),
                        )
                        .expect("failed to query transform HTTP response")
                ),
                OutCallHttpResponse
            )
            .unwrap();
        }
        let http_response = CanisterHttpResponsePayload {
            status: response.status.0.try_into().unwrap(),
            headers: response
                .headers
                .into_iter()
                .map(|h| ic_ic00_types::HttpHeader {
                    name: h.name,
                    value: h.value,
                })
                .collect(),
            body: response.body,
        };
        let payload = PayloadBuilder::new().http_response(*id, &http_response);
        self.setup.env.execute_payload(payload);
        self
    }

    pub fn wait(self) -> R {
        let candid = &assert_reply(
            self.setup
                .env
                .await_ingress(self.message_id, MAX_TICKS)
                .unwrap_or_else(|err| {
                    panic!("error during update call to `{}()`: {}", self.method, err)
                }),
        );
        Decode!(candid, R).expect("error while decoding Candid response from update call")
    }
}

#[test]
fn should_register_provider() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::RegisterProvider);
    assert_eq!(
        setup
            .get_providers()
            .into_iter()
            .map(|p| (p.chain_id, p.hostname))
            .collect::<Vec<_>>(),
        get_default_providers()
            .into_iter()
            .map(|p| (p.chain_id, p.hostname))
            .collect::<Vec<_>>()
    );
    let n_providers = 2;
    let a_id = setup
        .register_provider(RegisterProviderArgs {
            chain_id: 1,
            hostname: ANKR_HOSTNAME.to_string(),
            credential_path: "".to_string(),
            credential_headers: None,
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        })
        .wait();
    let b_id = setup
        .register_provider(RegisterProviderArgs {
            chain_id: 5,
            hostname: CLOUDFLARE_ETH_HOSTNAME.to_string(),
            credential_path: "/test-path".to_string(),
            credential_headers: Some(vec![HttpHeader {
                name: "Test-Authorization".to_string(),
                value: "---".to_string(),
            }]),
            cycles_per_call: 0,
            cycles_per_message_byte: 0,
        })
        .wait();
    assert_eq!(a_id + 1, b_id);
    let providers = setup.get_providers();
    assert_eq!(providers.len(), get_default_providers().len() + n_providers);
    let first_new_id = (providers.len() - n_providers) as u64;
    assert_eq!(
        providers[providers.len() - n_providers..],
        vec![
            ProviderView {
                provider_id: first_new_id,
                owner: setup.caller.0,
                chain_id: 1,
                hostname: ANKR_HOSTNAME.to_string(),
                cycles_per_call: 0,
                cycles_per_message_byte: 0,
                primary: false,
            },
            ProviderView {
                provider_id: first_new_id + 1,
                owner: setup.caller.0,
                chain_id: 5,
                hostname: CLOUDFLARE_ETH_HOSTNAME.to_string(),
                cycles_per_call: 0,
                cycles_per_message_byte: 0,
                primary: false,
            }
        ]
    )
}

fn mock_request(builder_fn: impl Fn(MockOutcallBuilder) -> MockOutcallBuilder) {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);

    assert_matches!(
        setup
            .request(
                Source::Custom {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: Some(vec![HttpHeader {
                        name: "Custom".to_string(),
                        value: "Value".to_string(),
                    }]),
                },
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .mock_http(builder_fn(MockOutcallBuilder::new(
                200,
                MOCK_REQUEST_RESPONSE
            )))
            .wait(),
        Ok(_)
    );
}

#[test]
fn mock_request_should_succeed() {
    mock_request(|builder| builder)
}

#[test]
fn mock_request_should_succeed_with_url() {
    mock_request(|builder| builder.with_url(MOCK_REQUEST_URL))
}

#[test]
fn mock_request_should_succeed_with_method() {
    mock_request(|builder| builder.with_method(HttpMethod::POST))
}

#[test]
fn mock_request_should_succeed_with_request_headers() {
    mock_request(|builder| {
        builder.with_request_headers(vec![
            (CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE),
            ("Custom", "Value"),
        ])
    })
}

#[test]
fn mock_request_should_succeed_with_request_body() {
    mock_request(|builder| builder.with_request_body(MOCK_REQUEST_PAYLOAD))
}

#[test]
fn mock_request_should_succeed_with_all() {
    mock_request(|builder| {
        builder
            .with_url(MOCK_REQUEST_URL)
            .with_method(HttpMethod::POST)
            .with_request_headers(vec![
                (CONTENT_TYPE_HEADER, CONTENT_TYPE_VALUE),
                ("Custom", "Value"),
            ])
            .with_request_body(MOCK_REQUEST_PAYLOAD)
    })
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn mock_request_should_fail_with_url() {
    mock_request(|builder| builder.with_url("https://not-the-url.com"))
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn mock_request_should_fail_with_method() {
    mock_request(|builder| builder.with_method(HttpMethod::GET))
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn mock_request_should_fail_with_request_headers() {
    mock_request(|builder| builder.with_request_headers(vec![("Custom", "NotValue")]))
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn mock_request_should_fail_with_request_body() {
    mock_request(|builder| builder.with_request_body(r#"{"different":"body"}"#))
}

#[test]
fn should_canonicalize_json_response() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let responses = [
        r#"{"id":1,"jsonrpc":"2.0","result":"0x00112233"}"#,
        r#"{"result":"0x00112233","id":1,"jsonrpc":"2.0"}"#,
        r#"{"result":"0x00112233","jsonrpc":"2.0","id":1}"#,
    ]
    .into_iter()
    .map(|response| {
        setup
            .request(
                Source::Custom {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: None,
                },
                MOCK_REQUEST_PAYLOAD,
                MOCK_REQUEST_RESPONSE_BYTES,
            )
            .mock_http(MockOutcallBuilder::new(200, response))
            .wait()
    })
    .collect::<Vec<_>>();
    assert!(responses.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn eth_get_logs_should_succeed() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let result = setup
        .eth_get_logs(
            CandidRpcSource::EthMainnet(None),
            candid_types::GetLogsArgs {
                addresses: vec!["0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string()],
                from_block:None,
                to_block:None,
                topics:None
            },
        )
        .mock_http(MockOutcallBuilder::new(200, r#"{"id":5,"jsonrpc":"2.0","result":[{"address":"0xdac17f958d2ee523a2206206994597c13d831ec7","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43","0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2"],"data":"0x000000000000000000000000000000000000000000000000000000003b9c6433","blockNumber":"0x11dc77e","transactionHash":"0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678","transactionIndex":"0x65","blockHash":"0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629","logIndex":"0xe8","removed":false}]}"#))
        .wait().unwrap();
    assert_eq!(result.len(), 1);
}

#[test]
fn eth_get_block_by_number_should_succeed() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let result = setup
        .eth_get_block_by_number(
            CandidRpcSource::EthMainnet(None),
            candid_types::BlockSpec::Tag(candid_types::BlockTag::Latest),
        )
        .mock_http(MockOutcallBuilder::new(200, "{\"jsonrpc\":\"2.0\",\"result\":{\"baseFeePerGas\":\"0xd7232aa34\",\"difficulty\":\"0x0\",\"extraData\":\"0x546974616e2028746974616e6275696c6465722e78797a29\",\"gasLimit\":\"0x1c9c380\",\"gasUsed\":\"0xa768c4\",\"hash\":\"0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae\",\"logsBloom\":\"0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b\",\"miner\":\"0x388c818ca8b9251b393131c08a736a67ccb19297\",\"mixHash\":\"0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f\",\"nonce\":\"0x0000000000000000\",\"number\":\"0x11db01d\",\"parentHash\":\"0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae\",\"receiptsRoot\":\"0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929\",\"sha3Uncles\":\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",\"size\":\"0xcd35\",\"stateRoot\":\"0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6\",\"timestamp\":\"0x656f96f3\",\"totalDifficulty\":\"0xc70d815d562d3cfa955\",\"withdrawalsRoot\":\"0xecae44b2c53871003c5cc75285995764034c9b5978a904229d36c1280b141d48\"},\"id\":0}"))
        .wait().unwrap();
    assert_eq!(
        result,
        Block {
            number: BlockNumber::new(18_722_845),
            base_fee_per_gas: Wei::new(57_750_497_844),
        }
    );
}

#[test]
fn eth_get_transaction_receipt_should_succeed() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let result = setup
        .eth_get_transaction_receipt(
            CandidRpcSource::EthMainnet(None),
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(200, "{\"jsonrpc\":\"2.0\",\"result\":{\"baseFeePerGas\":\"0xd7232aa34\",\"difficulty\":\"0x0\",\"extraData\":\"0x546974616e2028746974616e6275696c6465722e78797a29\",\"gasLimit\":\"0x1c9c380\",\"gasUsed\":\"0xa768c4\",\"hash\":\"0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae\",\"logsBloom\":\"0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b\",\"miner\":\"0x388c818ca8b9251b393131c08a736a67ccb19297\",\"mixHash\":\"0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f\",\"nonce\":\"0x0000000000000000\",\"number\":\"0x11db01d\",\"parentHash\":\"0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae\",\"receiptsRoot\":\"0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929\",\"sha3Uncles\":\"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347\",\"size\":\"0xcd35\",\"stateRoot\":\"0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6\",\"timestamp\":\"0x656f96f3\",\"totalDifficulty\":\"0xc70d815d562d3cfa955\",\"withdrawalsRoot\":\"0xecae44b2c53871003c5cc75285995764034c9b5978a904229d36c1280b141d48\"},\"id\":0}"))
        .wait().unwrap().expect("receipt was None");
    assert_eq!(result.block_number, BlockNumber::new(18_515_371));
}

#[test]
fn eth_get_transaction_count_should_succeed() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let result = setup
        .eth_get_transaction_count(
            CandidRpcSource::EthMainnet(None),
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#,
        ))
        .wait()
        .unwrap();
    assert_eq!(result, 1);
}

#[test]
fn should_allow_unexpected_response_fields() {
    let setup = EvmRpcSetup::new().authorize_caller(Auth::FreeRpc);
    let receipt = setup
        .eth_get_transaction_receipt(
            CandidRpcSource::EthMainnet(None),
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":1,"result":{"unexpectedKey":"unexpectedValue","blockHash":"0xb3b20624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35","blockNumber":"0x5bad55","contractAddress":null,"cumulativeGasUsed":"0xb90b0","effectiveGasPrice":"0x746a528800","from":"0x398137383b3d25c92898c656696e41950e47316b","gasUsed":"0x1383f","logs":[],"status":"0x1","to":"0x06012c8cf97bead5deae237070f9587f8e7a266d","transactionHash":"0xbb3a336e3f823ec18197f1e13ee875700f08f03e2cab75f0d0b118dabb44cba0","transactionIndex":"0x11","type":"0x0"}}"#))
        .wait().unwrap().expect("received `None` in place of receipt");
    assert_eq!(
        receipt.block_hash,
        FromStr::from_str("0xb3b20624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35")
            .unwrap()
    );
}
