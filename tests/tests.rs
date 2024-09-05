mod mock;

use std::{marker::PhantomData, rc::Rc, str::FromStr, time::Duration};

use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Nat};
use cketh_common::{
    address::Address,
    checked_amount::CheckedAmountOf,
    eth_rpc::{Block, Hash, HttpOutcallError, JsonRpcError, ProviderError, RpcError},
    eth_rpc_client::{
        providers::{EthMainnetService, EthSepoliaService, RpcApi, RpcService},
        RpcConfig,
    },
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
use maplit::hashmap;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use evm_rpc::{
    constants::{CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE},
    providers::PROVIDERS,
    types::{
        candid_types, InitArgs, Metrics, MultiRpcResult, ProviderId, RpcAccess, RpcMethod,
        RpcResult, RpcServices,
    },
};
use evm_rpc_types::Nat256;
use mock::{MockOutcall, MockOutcallBuilder};

const DEFAULT_CALLER_TEST_ID: u64 = 10352385;
const DEFAULT_CONTROLLER_TEST_ID: u64 = 10352386;
const ADDITIONAL_TEST_ID: u64 = 10352387;

const INITIAL_CYCLES: u128 = 100_000_000_000_000_000;

const MAX_TICKS: usize = 10;

const MOCK_REQUEST_URL: &str = "https://cloudflare-eth.com";
const MOCK_REQUEST_PAYLOAD: &str = r#"{"id":1,"jsonrpc":"2.0","method":"eth_gasPrice"}"#;
const MOCK_REQUEST_RESPONSE: &str = r#"{"id":1,"jsonrpc":"2.0","result":"0x00112233"}"#;
const MOCK_REQUEST_RESPONSE_BYTES: u64 = 1000;

const MOCK_TRANSACTION: &str="0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
const MOCK_TRANSACTION_HASH: &str =
    "0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788";

const RPC_SERVICES: &[RpcServices] = &[
    RpcServices::EthMainnet(None),
    RpcServices::EthSepolia(None),
    RpcServices::ArbitrumOne(None),
    RpcServices::BaseMainnet(None),
    RpcServices::OptimismMainnet(None),
];

const ANKR_HOSTNAME: &str = "rpc.ankr.com";
const ALCHEMY_ETH_MAINNET_HOSTNAME: &str = "eth-mainnet.g.alchemy.com";
const CLOUDFLARE_HOSTNAME: &str = "cloudflare-eth.com";
const BLOCKPI_ETH_SEPOLIA_HOSTNAME: &str = "ethereum-sepolia.blockpi.network";
const PUBLICNODE_ETH_MAINNET_HOSTNAME: &str = "ethereum-rpc.publicnode.com";

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
        Self::with_args(InitArgs {
            manage_api_keys: None,
            demo: Some(true),
        })
    }

    pub fn with_args(args: InitArgs) -> Self {
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
        env.install_existing_canister(canister_id, evm_rpc_wasm(), Encode!(&args).unwrap())
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

    /// Shorthand for deriving an `EvmRpcSetup` with a third-party caller.
    pub fn as_user(mut self) -> Self {
        self.caller = PrincipalId::new_user_test_id(DEFAULT_CONTROLLER_TEST_ID);
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

    pub fn get_metrics(&self) -> Metrics {
        self.call_query("getMetrics", Encode!().unwrap())
    }

    pub fn get_service_provider_map(&self) -> Vec<(RpcService, ProviderId)> {
        self.call_query("getServiceProviderMap", Encode!().unwrap())
    }

    pub fn request_cost(
        &self,
        source: RpcService,
        json_rpc_payload: &str,
        max_response_bytes: u64,
    ) -> Nat {
        self.call_query(
            "requestCost",
            Encode!(&source, &json_rpc_payload, &max_response_bytes).unwrap(),
        )
    }

    pub fn request(
        &self,
        source: RpcService,
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
        source: RpcServices,
        config: Option<RpcConfig>,
        args: evm_rpc_types::GetLogsArgs,
    ) -> CallFlow<MultiRpcResult<Vec<evm_rpc_types::LogEntry>>> {
        self.call_update("eth_getLogs", Encode!(&source, &config, &args).unwrap())
    }

    pub fn eth_get_block_by_number(
        &self,
        source: RpcServices,
        config: Option<RpcConfig>,
        block: candid_types::BlockTag,
    ) -> CallFlow<MultiRpcResult<Block>> {
        self.call_update(
            "eth_getBlockByNumber",
            Encode!(&source, &config, &block).unwrap(),
        )
    }

    pub fn eth_get_transaction_receipt(
        &self,
        source: RpcServices,
        config: Option<RpcConfig>,
        tx_hash: &str,
    ) -> CallFlow<MultiRpcResult<Option<evm_rpc_types::TransactionReceipt>>> {
        self.call_update(
            "eth_getTransactionReceipt",
            Encode!(&source, &config, &tx_hash).unwrap(),
        )
    }

    pub fn eth_get_transaction_count(
        &self,
        source: RpcServices,
        config: Option<RpcConfig>,
        args: candid_types::GetTransactionCountArgs,
    ) -> CallFlow<MultiRpcResult<Nat>> {
        self.call_update(
            "eth_getTransactionCount",
            Encode!(&source, &config, &args).unwrap(),
        )
    }

    pub fn eth_fee_history(
        &self,
        source: RpcServices,
        config: Option<RpcConfig>,
        args: evm_rpc_types::FeeHistoryArgs,
    ) -> CallFlow<MultiRpcResult<Option<evm_rpc_types::FeeHistory>>> {
        self.call_update("eth_feeHistory", Encode!(&source, &config, &args).unwrap())
    }

    pub fn eth_send_raw_transaction(
        &self,
        source: RpcServices,
        config: Option<RpcConfig>,
        signed_raw_transaction_hex: &str,
    ) -> CallFlow<MultiRpcResult<candid_types::SendRawTransactionStatus>> {
        self.call_update(
            "eth_sendRawTransaction",
            Encode!(&source, &config, &signed_raw_transaction_hex).unwrap(),
        )
    }

    pub fn update_api_keys(&self, api_keys: &[(ProviderId, Option<String>)]) {
        self.call_update("updateApiKeys", Encode!(&api_keys).unwrap())
            .wait()
    }

    pub fn mock_api_keys(self) -> Self {
        self.clone().as_controller().update_api_keys(
            &PROVIDERS
                .iter()
                .filter_map(|provider| {
                    Some((
                        provider.provider_id,
                        match provider.access {
                            RpcAccess::Authenticated { .. } => Some("mock-api-key".to_string()),
                            RpcAccess::Unauthenticated { .. } => None?,
                        },
                    ))
                })
                .collect::<Vec<_>>(),
        );
        self
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
        self.mock_http_once_inner(&mock);
        loop {
            if !self.try_mock_http_inner(&mock) {
                break;
            }
        }
        self
    }

    pub fn mock_http_n_times(self, mock: impl Into<MockOutcall>, count: u32) -> Self {
        let mock = mock.into();
        for _ in 0..count {
            self.mock_http_once_inner(&mock);
        }
        self
    }

    pub fn mock_http_once(self, mock: impl Into<MockOutcall>) -> Self {
        let mock = mock.into();
        self.mock_http_once_inner(&mock);
        self
    }

    fn mock_http_once_inner(&self, mock: &MockOutcall) {
        if !self.try_mock_http_inner(mock) {
            panic!("no pending HTTP request")
        }
    }

    fn try_mock_http_inner(&self, mock: &MockOutcall) -> bool {
        if self.setup.env.canister_http_request_contexts().is_empty() {
            self.setup.tick_until_http_request();
        }
        match self.setup.env.ingress_status(&self.message_id) {
            IngressStatus::Known { state, .. } if state != IngressState::Processing => {
                return false
            }
            _ => (),
        }
        let contexts = self.setup.env.canister_http_request_contexts();
        let (id, context) = match contexts.first_key_value() {
            Some(kv) => kv,
            None => return false,
        };

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
            status: mock.response.status.clone(),
            headers: mock.response.headers.clone(),
            body: mock.response.body.clone(),
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
        true
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

fn mock_request(builder_fn: impl Fn(MockOutcallBuilder) -> MockOutcallBuilder) {
    let setup = EvmRpcSetup::new();
    assert_matches!(
        setup
            .request(
                RpcService::Custom(RpcApi {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: Some(vec![HttpHeader {
                        name: "Custom".to_string(),
                        value: "Value".to_string(),
                    }]),
                }),
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
            (CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE),
            ("Custom", "Value"),
        ])
    })
}

#[test]
fn mock_request_should_succeed_with_request_body() {
    mock_request(|builder| builder.with_request_body(MOCK_REQUEST_PAYLOAD))
}

#[test]
fn mock_request_should_succeed_with_max_response_bytes() {
    mock_request(|builder| builder.with_max_response_bytes(MOCK_REQUEST_RESPONSE_BYTES))
}

#[test]
fn mock_request_should_succeed_with_all() {
    mock_request(|builder| {
        builder
            .with_url(MOCK_REQUEST_URL)
            .with_method(HttpMethod::POST)
            .with_request_headers(vec![
                (CONTENT_TYPE_HEADER_LOWERCASE, CONTENT_TYPE_VALUE),
                ("Custom", "Value"),
            ])
            .with_request_body(MOCK_REQUEST_PAYLOAD)
    })
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn mock_request_should_fail_with_url() {
    mock_request(|builder| builder.with_url("https://not-the-url.com"))
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn mock_request_should_fail_with_method() {
    mock_request(|builder| builder.with_method(HttpMethod::GET))
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn mock_request_should_fail_with_request_headers() {
    mock_request(|builder| builder.with_request_headers(vec![("Custom", "NotValue")]))
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn mock_request_should_fail_with_request_body() {
    mock_request(|builder| builder.with_request_body(r#"{"different":"body"}"#))
}

#[test]
fn should_canonicalize_json_response() {
    let setup = EvmRpcSetup::new();
    let responses = [
        r#"{"id":1,"jsonrpc":"2.0","result":"0x00112233"}"#,
        r#"{"result":"0x00112233","id":1,"jsonrpc":"2.0"}"#,
        r#"{"result":"0x00112233","jsonrpc":"2.0","id":1}"#,
    ]
    .into_iter()
    .map(|response| {
        setup
            .request(
                RpcService::Custom(RpcApi {
                    url: MOCK_REQUEST_URL.to_string(),
                    headers: None,
                }),
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
fn should_decode_renamed_field() {
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, CandidType)]
    pub struct Struct {
        #[serde(rename = "fieldName")]
        pub field_name: u64,
    }
    let value = Struct { field_name: 123 };
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Struct).unwrap(), value);
}

#[test]
fn should_decode_checked_amount() {
    let value = Wei::new(123);
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Wei).unwrap(), value);
}

#[test]
fn should_decode_address() {
    let value = Address::from_str("0xdAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    assert_eq!(Decode!(&Encode!(&value).unwrap(), Address).unwrap(), value);
}

#[test]
fn should_decode_transaction_receipt() {
    let value = evm_rpc_types::TransactionReceipt {
        status: 0x1_u8.into(),
        transaction_hash: "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"
            .parse()
            .unwrap(),
        contract_address: None,
        block_number: 18_515_371_u64.into(),
        block_hash: "0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be"
            .parse()
            .unwrap(),
        effective_gas_price: 26_776_497_782_u64.into(),
        gas_used: 32_137_u32.into(),
        from: "0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667"
            .parse()
            .unwrap(),
        logs: vec![],
        logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
        to: "0x356cfd6e6d0000400000003900b415f80669009e"
            .parse()
            .unwrap(),
        transaction_index: 0xd9_u16.into(),
        tx_type: "0x2".parse().unwrap(),
    };
    assert_eq!(
        Decode!(&Encode!(&value).unwrap(), evm_rpc_types::TransactionReceipt).unwrap(),
        value
    );
}

#[test]
fn should_use_fallback_public_url() {
    let authorized_caller = PrincipalId::new_user_test_id(ADDITIONAL_TEST_ID);
    let setup = EvmRpcSetup::with_args(InitArgs {
        demo: Some(true),
        manage_api_keys: Some(vec![authorized_caller.0]),
    });
    let response = setup
        .eth_get_transaction_count(
            RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])),
            None,
            candid_types::GetTransactionCountArgs {
                address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
                block: candid_types::BlockTag::Latest,
            },
        )
        .mock_http(
            MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#)
                .with_url("https://rpc.ankr.com/eth"),
        )
        .wait()
        .expect_consistent()
        .unwrap();
    assert_eq!(response, 1);
}

#[test]
fn should_insert_api_keys() {
    let authorized_caller = PrincipalId::new_user_test_id(ADDITIONAL_TEST_ID);
    let setup = EvmRpcSetup::with_args(InitArgs {
        demo: Some(true),
        manage_api_keys: Some(vec![authorized_caller.0]),
    });
    let provider_id = 1;
    setup
        .clone()
        .as_caller(authorized_caller)
        .update_api_keys(&[(provider_id, Some("test-api-key".to_string()))]);
    let response = setup
        .eth_get_transaction_count(
            RpcServices::EthMainnet(Some(vec![EthMainnetService::Ankr])),
            None,
            candid_types::GetTransactionCountArgs {
                address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
                block: candid_types::BlockTag::Latest,
            },
        )
        .mock_http(
            MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#)
                .with_url("https://rpc.ankr.com/eth/test-api-key"),
        )
        .wait()
        .expect_consistent()
        .unwrap();
    assert_eq!(response, 1);
}

#[test]
#[should_panic(expected = "You are not authorized")]
fn should_prevent_unauthorized_update_api_keys() {
    let setup = EvmRpcSetup::new();
    setup.update_api_keys(&[(0, Some("unauthorized-api-key".to_string()))]);
}

#[test]
fn eth_get_logs_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
        .eth_get_logs(
            source.clone(),
            None,
            evm_rpc_types::GetLogsArgs {
                addresses: vec!["0xdAC17F958D2ee523a2206206994597C13D831ec7".parse().unwrap()],
                from_block: None,
                to_block: None,
                topics: None,
            },
        )
        .mock_http(MockOutcallBuilder::new(200, r#"{"id":0,"jsonrpc":"2.0","result":[{"address":"0xdac17f958d2ee523a2206206994597c13d831ec7","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43","0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2"],"data":"0x000000000000000000000000000000000000000000000000000000003b9c6433","blockNumber":"0x11dc77e","transactionHash":"0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678","transactionIndex":"0x65","blockHash":"0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629","logIndex":"0xe8","removed":false}]}"#))
        .wait()
        .expect_consistent()
        .unwrap();
        assert_eq!(
            response,
            vec![evm_rpc_types::LogEntry {
                address: "0xdac17f958d2ee523a2206206994597c13d831ec7"
                    .parse()
                    .unwrap(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    "0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43",
                    "0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2"
                ]
                .into_iter()
                .map(|hex| hex.parse().unwrap())
                .collect(),
                data: "0x000000000000000000000000000000000000000000000000000000003b9c6433"
                    .parse()
                    .unwrap(),
                block_number: Some(0x11dc77e_u32.into()),
                transaction_hash: Some(
                    "0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678"
                        .parse()
                        .unwrap()
                ),
                transaction_index: Some(0x65_u32.into()),
                block_hash: Some(
                    "0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629"
                        .parse()
                        .unwrap()
                ),
                log_index: Some(0xe8_u32.into()),
                removed: false
            }]
        );
    }
}

#[test]
fn eth_get_block_by_number_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
            .eth_get_block_by_number(
                source.clone(),
                None,
                candid_types::BlockTag::Latest,
            )
            .mock_http(MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","result":{"baseFeePerGas":"0xd7232aa34","difficulty":"0x0","extraData":"0x546974616e2028746974616e6275696c6465722e78797a29","gasLimit":"0x1c9c380","gasUsed":"0xa768c4","hash":"0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae","logsBloom":"0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b","miner":"0x388c818ca8b9251b393131c08a736a67ccb19297","mixHash":"0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f","nonce":"0x0000000000000000","number":"0x11db01d","parentHash":"0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae","receiptsRoot":"0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0xcd35","stateRoot":"0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6","timestamp":"0x656f96f3","totalDifficulty":"0xc70d815d562d3cfa955","withdrawalsRoot":"0xecae44b2c53871003c5cc75285995764034c9b5978a904229d36c1280b141d48"},"id":0}"#))
            .wait()
            .expect_consistent()
            .unwrap();
        assert_eq!(
            response,
            Block {
                base_fee_per_gas: Some(Wei::new(57_750_497_844)),
                difficulty: Some(CheckedAmountOf::new(0)),
                extra_data: "0x546974616e2028746974616e6275696c6465722e78797a29".to_string(),
                gas_limit: CheckedAmountOf::new(0x1c9c380),
                gas_used: CheckedAmountOf::new(0xa768c4),
                hash: "0xc3674be7b9d95580d7f23c03d32e946f2b453679ee6505e3a778f003c5a3cfae".to_string(),
                logs_bloom: "0x3e6b8420e1a13038902c24d6c2a9720a7ad4860cdc870cd5c0490011e43631134f608935bd83171247407da2c15d85014f9984608c03684c74aad48b20bc24022134cdca5f2e9d2dee3b502a8ccd39eff8040b1d96601c460e119c408c620b44fa14053013220847045556ea70484e67ec012c322830cf56ef75e09bd0db28a00f238adfa587c9f80d7e30d3aba2863e63a5cad78954555966b1055a4936643366a0bb0b1bac68d0e6267fc5bf8304d404b0c69041125219aa70562e6a5a6362331a414a96d0716990a10161b87dd9568046a742d4280014975e232b6001a0360970e569d54404b27807d7a44c949ac507879d9d41ec8842122da6772101bc8b".to_string(),
                miner: "0x388c818ca8b9251b393131c08a736a67ccb19297".to_string(),
                mix_hash: "0x516a58424d4883a3614da00a9c6f18cd5cd54335a08388229a993a8ecf05042f".to_string(),
                nonce: CheckedAmountOf::new(0),
                number: BlockNumber::new(18_722_845),
                parent_hash: "0x43325027f6adf9befb223f8ae80db057daddcd7b48e41f60cd94bfa8877181ae".to_string(),
                receipts_root: "0x66934c3fd9c547036fe0e56ad01bc43c84b170be7c4030a86805ddcdab149929".to_string(),
                sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".to_string(),
                size: CheckedAmountOf::new(0xcd35),
                state_root: "0x13552447dd62f11ad885f21a583c4fa34144efe923c7e35fb018d6710f06b2b6".to_string(),
                timestamp: CheckedAmountOf::new(0x656f96f3),
                total_difficulty: Some(CheckedAmountOf::new(0xc70d815d562d3cfa955)),
                transactions: vec![],
                transactions_root: None,
                uncles: vec![],
            }
        );
    }
}

#[test]
fn eth_get_block_by_number_pre_london_fork_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
            .eth_get_block_by_number(
                source.clone(),
                None,
                candid_types::BlockTag::Latest,
            )
            .mock_http(MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":1,"result":{"number":"0x0","hash":"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3","transactions":[],"totalDifficulty":"0x400000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","extraData":"0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa","nonce":"0x0000000000000042","miner":"0x0000000000000000000000000000000000000000","difficulty":"0x400000000","gasLimit":"0x1388","gasUsed":"0x0","uncles":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x21c","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","stateRoot":"0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x0"}}"#))
            .wait()
            .expect_consistent()
            .unwrap();
        assert_eq!(
            response,
            Block {
                base_fee_per_gas: None,
                difficulty: Some(CheckedAmountOf::new(0x400000000)),
                extra_data: "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa".to_string(),
                gas_limit: CheckedAmountOf::new(0x1388),
                gas_used: CheckedAmountOf::new(0x0),
                hash: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3".to_string(),
                logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                miner: "0x0000000000000000000000000000000000000000".to_string(),
                mix_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                nonce: CheckedAmountOf::new(0x0000000000000042),
                number: BlockNumber::new(0),
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                receipts_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
                sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".to_string(),
                size: CheckedAmountOf::new(0x21c),
                state_root: "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544".to_string(),
                timestamp: CheckedAmountOf::new(0x0),
                total_difficulty: Some(CheckedAmountOf::new(0x400000000)),
                transactions: vec![],
                transactions_root: Some("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string()),
                uncles: vec![],
            }
        );
    }
}

#[test]
fn eth_get_transaction_receipt_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
        .eth_get_transaction_receipt(
            source.clone(),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":2,"result":{"blockHash":"0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be","blockNumber":"0x11a85ab","contractAddress":null,"cumulativeGasUsed":"0xf02aed","effectiveGasPrice":"0x63c00ee76","from":"0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667","gasUsed":"0x7d89","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","status":"0x1","to":"0x356cfd6e6d0000400000003900b415f80669009e","transactionHash":"0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f","transactionIndex":"0xd9","type":"0x2"}}"#))
        .wait()
        .expect_consistent()
        .unwrap();
        assert_eq!(
        response,
        Some(evm_rpc_types::TransactionReceipt {
            status: 0x1_u8.into(),
            transaction_hash: "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f".parse().unwrap(),
            contract_address: None,
            block_number: 0x11a85ab_u64.into(),
            block_hash: "0x5115c07eb1f20a9d6410db0916ed3df626cfdab161d3904f45c8c8b65c90d0be".parse().unwrap(),
            effective_gas_price: 0x63c00ee76_u64.into(),
            gas_used: 0x7d89_u32.into(),
            from: "0x0aa8ebb6ad5a8e499e550ae2c461197624c6e667".parse().unwrap(),
            logs: vec![],
            logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".parse().unwrap(),
            to: "0x356cfd6e6d0000400000003900b415f80669009e".parse().unwrap(),
            transaction_index: 0xd9_u16.into(),
            tx_type: "0x2".parse().unwrap(),
        })
    );
    }
}

#[test]
fn eth_get_transaction_count_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
            .eth_get_transaction_count(
                source.clone(),
                None,
                candid_types::GetTransactionCountArgs {
                    address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
                    block: candid_types::BlockTag::Latest,
                },
            )
            .mock_http(MockOutcallBuilder::new(
                200,
                r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#,
            ))
            .wait()
            .expect_consistent()
            .unwrap();
        assert_eq!(response, 1);
    }
}

#[test]
fn eth_fee_history_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
        .eth_fee_history(
            source.clone(),
            None,
            evm_rpc_types::FeeHistoryArgs {
                block_count: 3_u8.into(),
                newest_block: evm_rpc_types::BlockTag::Latest,
                reward_percentiles: None,
            },
        )
        .mock_http(MockOutcallBuilder::new(
            200,
            r#"{"id":0,"jsonrpc":"2.0","result":{"oldestBlock":"0x11e57f5","baseFeePerGas":["0x9cf6c61b9","0x97d853982","0x9ba55a0b0","0x9543bf98d"],"reward":[["0x0123"]]}}"#,
        ))
        .wait()
        .expect_consistent()
        .unwrap();
        assert_eq!(
            response,
            Some(evm_rpc_types::FeeHistory {
                oldest_block: Nat256::from(0x11e57f5_u64),
                base_fee_per_gas: vec![0x9cf6c61b9_u64, 0x97d853982, 0x9ba55a0b0, 0x9543bf98d]
                    .into_iter()
                    .map(Nat256::from)
                    .collect(),
                gas_used_ratio: vec![],
                reward: vec![vec![Nat256::from(0x0123_u32)]],
            })
        );
    }
}

#[test]
fn eth_send_raw_transaction_should_succeed() {
    for source in RPC_SERVICES {
        let setup = EvmRpcSetup::new().mock_api_keys();
        let response = setup
            .eth_send_raw_transaction(source.clone(), None, MOCK_TRANSACTION)
            .mock_http(MockOutcallBuilder::new(
                200,
                r#"{"id":0,"jsonrpc":"2.0","result":"Ok"}"#,
            ))
            .wait()
            .expect_consistent()
            .unwrap();
        assert_eq!(
            response,
            candid_types::SendRawTransactionStatus::Ok(Some(
                Hash::from_str(MOCK_TRANSACTION_HASH).unwrap()
            ))
        );
    }
}

#[test]
fn candid_rpc_should_allow_unexpected_response_fields() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let response = setup
        .eth_get_transaction_receipt(
            RpcServices::EthMainnet(None),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(200, r#"{"jsonrpc":"2.0","id":0,"result":{"unexpectedKey":"unexpectedValue","blockHash":"0xb3b20624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35","blockNumber":"0x5bad55","contractAddress":null,"cumulativeGasUsed":"0xb90b0","effectiveGasPrice":"0x746a528800","from":"0x398137383b3d25c92898c656696e41950e47316b","gasUsed":"0x1383f","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","status":"0x1","to":"0x06012c8cf97bead5deae237070f9587f8e7a266d","transactionHash":"0xbb3a336e3f823ec18197f1e13ee875700f08f03e2cab75f0d0b118dabb44cba0","transactionIndex":"0x11","type":"0x0"}}"#))
        .wait()
        .expect_consistent()
        .unwrap()
        .expect("receipt was None");
    assert_eq!(
        response.block_hash,
        "0xb3b20624f8f0f86eb50dd04688409e5cea4bd02d700bf6e79e9384d47d6a5a35"
            .parse()
            .unwrap()
    );
}

#[test]
fn candid_rpc_should_err_without_cycles() {
    let setup = EvmRpcSetup::with_args(InitArgs {
        demo: None,
        manage_api_keys: None,
    })
    .mock_api_keys();
    let result = setup
        .eth_get_transaction_receipt(
            RpcServices::EthMainnet(None),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .wait()
        .expect_consistent();
    assert_matches!(
        result,
        Err(RpcError::ProviderError(ProviderError::TooFewCycles {
            expected: _,
            received: 0,
        }))
    );
}

#[test]
fn candid_rpc_should_err_when_service_unavailable() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_get_transaction_receipt(
            RpcServices::EthMainnet(None),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(503, "Service unavailable"))
        .wait()
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::HttpOutcallError(
            cketh_common::eth_rpc::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: 503,
                body: "Service unavailable".to_string(),
                parsing_error: None,
            }
        ))
    );
    let rpc_method = || RpcMethod::EthGetTransactionReceipt.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into()) => 1,
                (rpc_method(), PUBLICNODE_ETH_MAINNET_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into(), 503.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into(), 503.into()) => 1,
                (rpc_method(), PUBLICNODE_ETH_MAINNET_HOSTNAME.into(), 503.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_recognize_json_error() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_get_transaction_receipt(
            RpcServices::EthSepolia(Some(vec![
                EthSepoliaService::Ankr,
                EthSepoliaService::BlockPi,
            ])),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .mock_http(MockOutcallBuilder::new(
            200,
            r#"{"jsonrpc":"2.0","id":0,"error":{"code":123,"message":"Error message"}}"#,
        ))
        .wait()
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::JsonRpcError(JsonRpcError {
            code: 123,
            message: "Error message".to_string(),
        }))
    );
    let rpc_method = || RpcMethod::EthGetTransactionReceipt.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), BLOCKPI_ETH_SEPOLIA_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into(), 200.into()) => 1,
                (rpc_method(), BLOCKPI_ETH_SEPOLIA_HOSTNAME.into(), 200.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_reject_empty_service_list() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_get_transaction_receipt(
            RpcServices::EthMainnet(Some(vec![])),
            None,
            "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f",
        )
        .wait()
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::ProviderError(ProviderError::ProviderNotFound))
    );
}

#[test]
fn candid_rpc_should_return_inconsistent_results() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let results = setup
        .eth_send_raw_transaction(
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Ankr,
                EthMainnetService::Cloudflare,
            ])),
            None,
            MOCK_TRANSACTION,
        )
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"id":0,"jsonrpc":"2.0","result":"Ok"}"#,
        ))
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"id":0,"jsonrpc":"2.0","result":"NonceTooLow"}"#,
        ))
        .wait()
        .expect_inconsistent();
    assert_eq!(
        results,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Ok(candid_types::SendRawTransactionStatus::Ok(Some(
                    Hash::from_str(MOCK_TRANSACTION_HASH).unwrap()
                )))
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Cloudflare),
                Ok(candid_types::SendRawTransactionStatus::NonceTooLow)
            )
        ]
    );
    let rpc_method = || RpcMethod::EthSendRawTransaction.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into(), 200.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into(), 200.into()) => 1,
            },
            inconsistent_responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_return_inconsistent_results_with_error() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_get_transaction_count(
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Alchemy,
                EthMainnetService::Ankr,
            ])),
            None,
            candid_types::GetTransactionCountArgs {
                address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
                block: candid_types::BlockTag::Latest,
            },
        )
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#,
        ))
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"jsonrpc":"2.0","id":0,"error":{"code":123,"message":"Unexpected"}}"#,
        ))
        .wait()
        .expect_inconsistent();
    assert_eq!(
        result,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::Alchemy),
                Ok(1.into())
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::JsonRpcError(JsonRpcError {
                    code: 123,
                    message: "Unexpected".to_string(),
                }))
            ),
        ]
    );
    let rpc_method = || RpcMethod::EthGetTransactionCount.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into(), 200.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into(), 200.into()) => 1,
            },
            inconsistent_responses: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_return_inconsistent_results_with_unexpected_http_status() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_get_transaction_count(
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Alchemy,
                EthMainnetService::Ankr,
            ])),
            None,
            candid_types::GetTransactionCountArgs {
                address: "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
                block: candid_types::BlockTag::Latest,
            },
        )
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"jsonrpc":"2.0","id":0,"result":"0x1"}"#,
        ))
        .mock_http_once(MockOutcallBuilder::new(
            400,
            r#"{"jsonrpc":"2.0","id":0,"error":{"code":123,"message":"Error message"}}"#,
        ))
        .wait()
        .expect_inconsistent();
    assert_eq!(
        result,
        vec![
            (
                RpcService::EthMainnet(EthMainnetService::Alchemy),
                Ok(1.into())
            ),
            (
                RpcService::EthMainnet(EthMainnetService::Ankr),
                Err(RpcError::HttpOutcallError(HttpOutcallError::InvalidHttpJsonRpcResponse {
                    status: 400,
                    body: "{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":123,\"message\":\"Error message\"}}".to_string(),
                    parsing_error: None,
                })),
            ),
        ]
    );
    let rpc_method = || RpcMethod::EthGetTransactionCount.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into(), 200.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into(), 400.into()) => 1,
            },
            inconsistent_responses: hashmap! {
                (rpc_method(), ALCHEMY_ETH_MAINNET_HOSTNAME.into()) => 1,
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_handle_already_known() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_send_raw_transaction(
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Ankr,
                EthMainnetService::Cloudflare,
            ])),
            None,
            MOCK_TRANSACTION,
        )
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"id":0,"jsonrpc":"2.0","result":"Ok"}"#,
        ))
        .mock_http_once(MockOutcallBuilder::new(
            200,
            r#"{"id":0,"jsonrpc":"2.0","error":{"code":-32000,"message":"already known"}}"#,
        ))
        .wait()
        .expect_consistent();
    assert_eq!(
        result,
        Ok(candid_types::SendRawTransactionStatus::Ok(Some(
            Hash::from_str(MOCK_TRANSACTION_HASH).unwrap()
        )))
    );
    let rpc_method = || RpcMethod::EthSendRawTransaction.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into(), 200.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into(), 200.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn candid_rpc_should_recognize_rate_limit() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let result = setup
        .eth_send_raw_transaction(
            RpcServices::EthMainnet(Some(vec![
                EthMainnetService::Ankr,
                EthMainnetService::Cloudflare,
            ])),
            None,
            MOCK_TRANSACTION,
        )
        .mock_http(MockOutcallBuilder::new(429, "(Rate limit error message)"))
        .wait()
        .expect_consistent();
    assert_eq!(
        result,
        Err(RpcError::HttpOutcallError(
            cketh_common::eth_rpc::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status: 429,
                body: "(Rate limit error message)".to_string(),
                parsing_error: None
            }
        ))
    );
    let rpc_method = || RpcMethod::EthSendRawTransaction.into();
    assert_eq!(
        setup.get_metrics(),
        Metrics {
            requests: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into()) => 1,
            },
            responses: hashmap! {
                (rpc_method(), ANKR_HOSTNAME.into(), 429.into()) => 1,
                (rpc_method(), CLOUDFLARE_HOSTNAME.into(), 429.into()) => 1,
            },
            ..Default::default()
        }
    );
}

#[test]
fn should_use_custom_response_size_estimate() {
    let setup = EvmRpcSetup::new().mock_api_keys();
    let max_response_bytes = 1234;
    let expected_response = r#"{"id":0,"jsonrpc":"2.0","result":[{"address":"0xdac17f958d2ee523a2206206994597c13d831ec7","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x000000000000000000000000a9d1e08c7793af67e9d92fe308d5697fb81d3e43","0x00000000000000000000000078cccfb3d517cd4ed6d045e263e134712288ace2"],"data":"0x000000000000000000000000000000000000000000000000000000003b9c6433","blockNumber":"0x11dc77e","transactionHash":"0xf3ed91a03ddf964281ac7a24351573efd535b80fc460a5c2ad2b9d23153ec678","transactionIndex":"0x65","blockHash":"0xd5c72ad752b2f0144a878594faf8bd9f570f2f72af8e7f0940d3545a6388f629","logIndex":"0xe8","removed":false}]}"#;
    let response = setup
        .eth_get_logs(
            RpcServices::EthMainnet(Some(vec![EthMainnetService::Cloudflare])),
            Some(RpcConfig {
                response_size_estimate: Some(max_response_bytes),
            }),
            evm_rpc_types::GetLogsArgs {
                addresses: vec!["0xdAC17F958D2ee523a2206206994597C13D831ec7"
                    .parse()
                    .unwrap()],
                from_block: None,
                to_block: None,
                topics: None,
            },
        )
        .mock_http_once(
            MockOutcallBuilder::new(200, expected_response)
                .with_max_response_bytes(max_response_bytes),
        )
        .wait()
        .expect_consistent();
    assert_matches!(response, Ok(_));
}
