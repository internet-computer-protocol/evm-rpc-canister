use cketh_common::eth_rpc_client::providers::SepoliaProvider;
use evm_rpc::{Auth, CandidRpcClient, CandidRpcSource};

const DEFAULT_CALLER_ID: u64 = 10352385;

fn evm_rpc_wasm() -> Vec<u8> {
    load_wasm(std::env::var("CARGO_MANIFEST_DIR").unwrap(), "evm_rpc", &[])
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        result => {
            panic!("Expected a successful reply, got {}", reject)
        }
    }
}

pub struct EvmRpcSetup {
    pub env: StateMachine,
    pub caller: PrincipalId,
    pub evm_rpc_id: CanisterId,
}

impl Default for EvmRpcSetup {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmRpcSetup {
    pub fn new() -> Self {
        let env = StateMachineBuilder::new()
            .with_default_canister_range()
            .build();

        let evm_rpc_id = env.create_canister(None);
        env.install_existing_canister(evm_rpc_id, evm_rpc_wasm(), Encode!(&()).unwrap())
            .unwrap();

        let caller = PrincipalId::new_user_test_id(DEFAULT_CALLER_ID);

        Self {
            env,
            caller,
            evm_rpc_id,
        }
    }

    // pub fn deposit(self, params: DepositParams) -> DepositFlow {
    //     DepositFlow {
    //         setup: self,
    //         params,
    //     }
    // }

    pub fn call_update<T, R>(&self, method: &str, input: &T) -> R {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.evm_rpc_id,
                        method,
                        Encode!(input).unwrap(),
                    )
                    .expect("error during update call")
            ),
            T
        )
        .unwrap()
    }

    pub fn call_query<T, R>(&self, method: &str, input: T) -> R {
        Decode!(
            &assert_reply(
                self.env
                    .query_as(
                        self.caller,
                        self.evm_rpc_id,
                        method,
                        Encode!(input).unwrap(),
                    )
                    .expect("error during query call")
            ),
            R
        )
        .unwrap()
    }

    pub fn authorize(self, auth: Auth) -> Self {
        assert!(self.call_update("authorize", ()));
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
            (source, json_rpc_payload, max_response_bytes),
        )
    }

    // pub fn call_ledger_approve_minter(
    //     self,
    //     from: Principal,
    //     amount: u64,
    //     from_subaccount: Option<[u8; 32]>,
    // ) -> ApprovalFlow {
    //     let approval_response = Decode!(&assert_reply(self.env.execute_ingress_as(
    //         PrincipalId::from(from),
    //         self.ledger_id,
    //         "icrc2_approve",
    //         Encode!(&ApproveArgs {
    //             from_subaccount,
    //             spender: Account {
    //                 owner: self.minter_id.into(),
    //                 subaccount: None
    //             },
    //             amount: Nat::from(amount),
    //             expected_allowance: None,
    //             expires_at: None,
    //             fee: None,
    //             memo: None,
    //             created_at_time: None,
    //         }).unwrap()
    //         ).expect("failed to execute token transfer")),
    //         Result<Nat, ApproveError>
    //     )
    //     .unwrap();
    //     ApprovalFlow {
    //         setup: self,
    //         approval_response,
    //     }
    // }

    // pub fn call_minter_withdraw_eth(
    //     self,
    //     from: Principal,
    //     amount: Nat,
    //     recipient: String,
    // ) -> WithdrawalFlow {
    //     let arg = WithdrawalArg { amount, recipient };
    //     let message_id = self.env.send_ingress(
    //         PrincipalId::from(from),
    //         self.minter_id,
    //         "withdraw_eth",
    //         Encode!(&arg).expect("failed to encode withdraw args"),
    //     );
    //     WithdrawalFlow {
    //         setup: self,
    //         message_id,
    //     }
    // }

    // pub fn _get_logs(&self, priority: &str) -> Log {
    //     let request = HttpRequest {
    //         method: "".to_string(),
    //         url: format!("/logs?priority={priority}"),
    //         headers: vec![],
    //         body: serde_bytes::ByteBuf::new(),
    //     };
    //     let response = Decode!(
    //         &assert_reply(
    //             self.env
    //                 .query(self.minter_id, "http_request", Encode!(&request).unwrap(),)
    //                 .expect("failed to get minter info")
    //         ),
    //         HttpResponse
    //     )
    //     .unwrap();
    //     serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    // }

    // pub fn assert_has_unique_events_in_order(self, expected_events: &[EventPayload]) -> Self {
    //     let audit_events = self.get_all_events();
    //     let mut found_event_indexes = BTreeMap::new();
    //     for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
    //         for (index_audit_event, audit_event) in audit_events.iter().enumerate() {
    //             if &audit_event.payload == expected_event {
    //                 assert_eq!(
    //                     found_event_indexes.insert(index_expected_event, index_audit_event),
    //                     None,
    //                     "Event {:?} occurs multiple times",
    //                     expected_event
    //                 );
    //             }
    //         }
    //         assert!(
    //             found_event_indexes.contains_key(&index_expected_event),
    //             "Missing event {:?}",
    //             expected_event
    //         )
    //     }
    //     let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
    //     let sorted_audit_event_indexes = {
    //         let mut indexes = audit_event_indexes.clone();
    //         indexes.sort_unstable();
    //         indexes
    //     };
    //     assert_eq!(
    //         audit_event_indexes, sorted_audit_event_indexes,
    //         "Events were found in unexpected order"
    //     );
    //     self
    // }

    // pub fn assert_has_no_event_satisfying<P: Fn(&EventPayload) -> bool>(
    //     self,
    //     predicate: P,
    // ) -> Self {
    //     if let Some(unexpected_event) = self
    //         .get_all_events()
    //         .into_iter()
    //         .find(|event| predicate(&event.payload))
    //     {
    //         panic!(
    //             "Found an event satisfying the predicate: {:?}",
    //             unexpected_event
    //         )
    //     }
    //     self
    // }

    // fn get_events(&self, start: u64, length: u64) -> GetEventsResult {
    //     use ic_cketh_minter::endpoints::events::GetEventsArg;

    //     Decode!(
    //         &assert_reply(
    //             self.env
    //                 .execute_ingress(
    //                     self.minter_id,
    //                     "get_events",
    //                     Encode!(&GetEventsArg { start, length }).unwrap(),
    //                 )
    //                 .expect("failed to get minter info")
    //         ),
    //         GetEventsResult
    //     )
    //     .unwrap()
    // }

    // pub fn get_all_events(&self) -> Vec<Event> {
    //     const FIRST_BATCH_SIZE: u64 = 100;
    //     let GetEventsResult {
    //         mut events,
    //         total_event_count,
    //     } = self.get_events(0, FIRST_BATCH_SIZE);
    //     while events.len() < total_event_count as usize {
    //         let mut next_batch =
    //             self.get_events(events.len() as u64, total_event_count - events.len() as u64);
    //         events.append(&mut next_batch.events);
    //     }
    //     events
    // }

    // fn check_audit_log(&self) {
    //     Decode!(
    //         &assert_reply(
    //             self.env
    //                 .query(self.minter_id, "check_audit_log", Encode!().unwrap())
    //                 .unwrap(),
    //         ),
    //         ()
    //     )
    //     .unwrap()
    // }

    // fn upgrade_minter(&self) {
    //     self.env
    //         .upgrade_canister(
    //             self.minter_id,
    //             minter_wasm(),
    //             Encode!(&MinterArg::UpgradeArg(Default::default())).unwrap(),
    //         )
    //         .unwrap();
    // }

    // fn check_audit_logs_and_upgrade(self) -> Self {
    //     self.check_audit_log();
    //     self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
    //     self.upgrade_minter();
    //     self
    // }
}

#[test]
fn test_register_provider() {
    let setup = EvmRpcSetup::new().authorize(Auth::RegisterProvider);

    // assert!(false);
}
