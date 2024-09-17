mod eth_rpc_client {
    use crate::rpc_client::EthRpcClient;
    use evm_rpc_types::{EthMainnetService, ProviderError, RpcService, RpcServices};

    #[test]
    fn should_fail_when_providers_explicitly_set_to_empty() {
        for empty_source in [
            RpcServices::Custom {
                chain_id: 1,
                services: vec![],
            },
            RpcServices::EthMainnet(Some(vec![])),
            RpcServices::EthSepolia(Some(vec![])),
            RpcServices::ArbitrumOne(Some(vec![])),
            RpcServices::BaseMainnet(Some(vec![])),
            RpcServices::OptimismMainnet(Some(vec![])),
        ] {
            assert_eq!(
                EthRpcClient::new(empty_source, None),
                Err(ProviderError::ProviderNotFound)
            );
        }
    }

    #[test]
    fn should_use_default_providers() {
        for empty_source in [
            RpcServices::EthMainnet(None),
            RpcServices::EthSepolia(None),
            RpcServices::ArbitrumOne(None),
            RpcServices::BaseMainnet(None),
            RpcServices::OptimismMainnet(None),
        ] {
            let client = EthRpcClient::new(empty_source, None).unwrap();
            assert!(!client.providers().is_empty());
        }
    }

    #[test]
    fn should_use_specified_provider() {
        let provider1 = EthMainnetService::Alchemy;
        let provider2 = EthMainnetService::PublicNode;

        let client = EthRpcClient::new(
            RpcServices::EthMainnet(Some(vec![provider1, provider2])),
            None,
        )
        .unwrap();

        assert_eq!(
            client.providers(),
            &[
                RpcService::EthMainnet(provider1),
                RpcService::EthMainnet(provider2)
            ]
        );
    }
}

mod multi_call_results {
    use evm_rpc_types::{EthMainnetService, RpcService};

    const ANKR: RpcService = RpcService::EthMainnet(EthMainnetService::Ankr);
    const PUBLIC_NODE: RpcService = RpcService::EthMainnet(EthMainnetService::PublicNode);
    const CLOUDFLARE: RpcService = RpcService::EthMainnet(EthMainnetService::Cloudflare);

    mod reduce_with_equality {
        use crate::rpc_client::eth_rpc::JsonRpcResult;
        use crate::rpc_client::tests::multi_call_results::{ANKR, PUBLIC_NODE};
        use crate::rpc_client::{MultiCallError, MultiCallResults};
        use evm_rpc_types::{HttpOutcallError, JsonRpcError, RpcError};
        use ic_cdk::api::call::RejectionCode;

        #[test]
        #[should_panic(expected = "MultiCallResults cannot be empty")]
        fn should_panic_when_empty() {
            let _panic = MultiCallResults::<String>::from_non_empty_iter(vec![]);
        }

        #[test]
        fn should_be_inconsistent_when_different_call_errors() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    })),
                ),
                (
                    PUBLIC_NODE,
                    Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                        code: RejectionCode::SysTransient,
                        message: "transient".to_string(),
                    })),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_inconsistent_when_different_rpc_errors() {
            let results: MultiCallResults<String> = MultiCallResults::from_json_rpc_result(vec![
                (
                    ANKR,
                    Ok(JsonRpcResult::Error {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Ok(JsonRpcResult::Error {
                        code: -32000,
                        message: "nonce too low".to_string(),
                    }),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_inconsistent_when_different_ok_results() {
            let results: MultiCallResults<String> = MultiCallResults::from_json_rpc_result(vec![
                (ANKR, Ok(JsonRpcResult::Result("hello".to_string()))),
                (PUBLIC_NODE, Ok(JsonRpcResult::Result("world".to_string()))),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)))
        }

        #[test]
        fn should_be_consistent_http_outcall_error() {
            let results: MultiCallResults<String> = MultiCallResults::from_non_empty_iter(vec![
                (
                    ANKR,
                    Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    })),
                ),
                (
                    PUBLIC_NODE,
                    Err(RpcError::HttpOutcallError(HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    })),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(
                reduced,
                Err(MultiCallError::ConsistentError(RpcError::HttpOutcallError(
                    HttpOutcallError::IcError {
                        code: RejectionCode::CanisterReject,
                        message: "reject".to_string(),
                    }
                )))
            );
        }

        #[test]
        fn should_be_consistent_rpc_error() {
            let results: MultiCallResults<String> = MultiCallResults::from_json_rpc_result(vec![
                (
                    ANKR,
                    Ok(JsonRpcResult::Error {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
                (
                    PUBLIC_NODE,
                    Ok(JsonRpcResult::Error {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }),
                ),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(
                reduced,
                Err(MultiCallError::ConsistentError(RpcError::JsonRpcError(
                    JsonRpcError {
                        code: -32700,
                        message: "insufficient funds for gas * price + value".to_string(),
                    }
                )))
            );
        }

        #[test]
        fn should_be_consistent_ok_result() {
            let results: MultiCallResults<String> = MultiCallResults::from_json_rpc_result(vec![
                (ANKR, Ok(JsonRpcResult::Result("0x01".to_string()))),
                (PUBLIC_NODE, Ok(JsonRpcResult::Result("0x01".to_string()))),
            ]);

            let reduced = results.clone().reduce_with_equality();

            assert_eq!(reduced, Ok("0x01".to_string()));
        }
    }

    mod reduce_with_stable_majority_by_key {
        use crate::rpc_client::eth_rpc::JsonRpcResult;
        use crate::rpc_client::numeric::{BlockNumber, WeiPerGas};
        use crate::rpc_client::tests::multi_call_results::{ANKR, CLOUDFLARE, PUBLIC_NODE};
        use crate::rpc_client::{MultiCallError, MultiCallResults};
        use crate::rpc_client::json::responses::FeeHistory;

        #[test]
        fn should_get_unanimous_fee_history() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_json_rpc_result(vec![
                    (ANKR, Ok(JsonRpcResult::Result(fee_history()))),
                    (PUBLIC_NODE, Ok(JsonRpcResult::Result(fee_history()))),
                    (CLOUDFLARE, Ok(JsonRpcResult::Result(fee_history()))),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(reduced, Ok(fee_history()));
        }

        #[test]
        fn should_get_fee_history_with_2_out_of_3() {
            for index_non_majority in 0..3_usize {
                let index_majority = (index_non_majority + 1) % 3;
                let mut fees = [fee_history(), fee_history(), fee_history()];
                fees[index_non_majority].oldest_block = BlockNumber::new(0x10f73fd);
                assert_ne!(
                    fees[index_non_majority].oldest_block,
                    fees[index_majority].oldest_block
                );
                let majority_fee = fees[index_majority].clone();
                let [ankr_fee_history, cloudflare_fee_history, public_node_fee_history] = fees;
                let results: MultiCallResults<FeeHistory> =
                    MultiCallResults::from_json_rpc_result(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history))),
                        (
                            CLOUDFLARE,
                            Ok(JsonRpcResult::Result(cloudflare_fee_history)),
                        ),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(public_node_fee_history)),
                        ),
                    ]);

                let reduced = results
                    .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

                assert_eq!(reduced, Ok(majority_fee));
            }
        }

        #[test]
        fn should_fail_when_no_strict_majority() {
            let ankr_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fd),
                ..fee_history()
            };
            let cloudflare_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fc),
                ..fee_history()
            };
            let public_node_fee_history = FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fe),
                ..fee_history()
            };
            let three_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_json_rpc_result(vec![
                    (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(public_node_fee_history.clone())),
                    ),
                ]);

            let reduced = three_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_json_rpc_result(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(public_node_fee_history))
                        ),
                    ])
                ))
            );

            let two_distinct_results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_json_rpc_result(vec![
                    (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(cloudflare_fee_history.clone())),
                    ),
                ]);

            let reduced = two_distinct_results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_json_rpc_result(vec![
                        (ANKR, Ok(JsonRpcResult::Result(ankr_fee_history))),
                        (
                            PUBLIC_NODE,
                            Ok(JsonRpcResult::Result(cloudflare_fee_history))
                        ),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_when_fee_history_inconsistent_for_same_oldest_block() {
            let (fee, inconsistent_fee) = {
                let fee = fee_history();
                let mut inconsistent_fee = fee.clone();
                inconsistent_fee.base_fee_per_gas[0] = WeiPerGas::new(0x729d3f3b4);
                assert_ne!(fee, inconsistent_fee);
                (fee, inconsistent_fee)
            };

            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_json_rpc_result(vec![
                    (ANKR, Ok(JsonRpcResult::Result(fee.clone()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Result(inconsistent_fee.clone())),
                    ),
                ]);

            let reduced =
                results.reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(
                reduced,
                Err(MultiCallError::InconsistentResults(
                    MultiCallResults::from_json_rpc_result(vec![
                        (ANKR, Ok(JsonRpcResult::Result(fee.clone()))),
                        (PUBLIC_NODE, Ok(JsonRpcResult::Result(inconsistent_fee))),
                    ])
                ))
            );
        }

        #[test]
        fn should_fail_upon_any_error() {
            let results: MultiCallResults<FeeHistory> =
                MultiCallResults::from_json_rpc_result(vec![
                    (ANKR, Ok(JsonRpcResult::Result(fee_history()))),
                    (
                        PUBLIC_NODE,
                        Ok(JsonRpcResult::Error {
                            code: -32700,
                            message: "error".to_string(),
                        }),
                    ),
                ]);

            let reduced = results
                .clone()
                .reduce_with_strict_majority_by_key(|fee_history| fee_history.oldest_block);

            assert_eq!(reduced, Err(MultiCallError::InconsistentResults(results)));
        }

        fn fee_history() -> FeeHistory {
            FeeHistory {
                oldest_block: BlockNumber::new(0x10f73fc),
                base_fee_per_gas: vec![
                    WeiPerGas::new(0x729d3f3b3),
                    WeiPerGas::new(0x766e503ea),
                    WeiPerGas::new(0x75b51b620),
                    WeiPerGas::new(0x74094f2b4),
                    WeiPerGas::new(0x716724f03),
                    WeiPerGas::new(0x73b467f76),
                ],
                gas_used_ratio: vec![
                    0.6332004,
                    0.47556506666666665,
                    0.4432122666666667,
                    0.4092196,
                    0.5811903,
                ],
                reward: vec![
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x55d4a80)],
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x5f5e100)],
                    vec![WeiPerGas::new(0x5f5e100)],
                ],
            }
        }
    }
}

mod eth_get_transaction_receipt {
    use crate::rpc_client::eth_rpc::Hash;
    use crate::rpc_client::numeric::{BlockNumber, GasAmount, WeiPerGas};
    use assert_matches::assert_matches;
    use proptest::proptest;
    use std::str::FromStr;
    use crate::rpc_client::json::responses::{TransactionReceipt, TransactionStatus};

    #[test]
    fn should_deserialize_transaction_receipt() {
        const RECEIPT: &str = r#"{
        "transactionHash": "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
        "blockHash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
        "blockNumber": "0x4132ec",
        "logs": [],
        "contractAddress": null,
        "effectiveGasPrice": "0xfefbee3e",
        "cumulativeGasUsed": "0x8b2e10",
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x01",
        "to": "0xdd2851cdd40ae6536831558dd46db62fac7a844d",
        "transactionIndex": "0x32",
        "type": "0x2"
    }"#;

        let receipt: TransactionReceipt = serde_json::from_str(RECEIPT).unwrap();

        assert_eq!(
            receipt,
            TransactionReceipt {
                block_hash: Hash::from_str(
                    "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4"
                )
                .unwrap(),
                block_number: BlockNumber::new(0x4132ec),
                effective_gas_price: WeiPerGas::new(0xfefbee3e),
                gas_used: GasAmount::new(0x5208),
                status: TransactionStatus::Success,
                transaction_hash: Hash::from_str(
                    "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"
                )
                .unwrap(),
                contract_address: None,
                from: "0x1789f79e95324a47c5fd6693071188e82e9a3558".to_string(),
                logs: vec![],
                logs_bloom: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                to: "0xdd2851cdd40ae6536831558dd46db62fac7a844d".to_string(),
                transaction_index: 0x32_u32.into(),
                r#type: "0x2".to_string(),
            }
        )
    }

    #[test]
    fn should_deserialize_transaction_status() {
        let status: TransactionStatus = serde_json::from_str("\"0x01\"").unwrap();
        assert_eq!(status, TransactionStatus::Success);

        // some providers do not return a full byte (2 hex digits) for the status
        let status: TransactionStatus = serde_json::from_str("\"0x1\"").unwrap();
        assert_eq!(status, TransactionStatus::Success);

        let status: TransactionStatus = serde_json::from_str("\"0x0\"").unwrap();
        assert_eq!(status, TransactionStatus::Failure);

        let status: TransactionStatus = serde_json::from_str("\"0x00\"").unwrap();
        assert_eq!(status, TransactionStatus::Failure);
    }

    #[test]
    fn should_deserialize_serialized_transaction_status() {
        let status: TransactionStatus =
            serde_json::from_str(&serde_json::to_string(&TransactionStatus::Success).unwrap())
                .unwrap();
        assert_eq!(status, TransactionStatus::Success);

        let status: TransactionStatus =
            serde_json::from_str(&serde_json::to_string(&TransactionStatus::Failure).unwrap())
                .unwrap();
        assert_eq!(status, TransactionStatus::Failure);
    }

    proptest! {
        #[test]
        fn should_fail_deserializing_wrong_transaction_status(wrong_status in 2_u32..u32::MAX) {
            let status = format!("\"0x{:x}\"", wrong_status);
            let error = serde_json::from_str::<TransactionStatus>(&status);
            assert_matches!(error, Err(e) if e.to_string().contains("invalid transaction status"));
        }
    }
}

mod eth_get_transaction_count {
    use crate::rpc_client::json::requests::{BlockSpec, BlockTag, GetTransactionCountParams};
    use crate::rpc_client::numeric::TransactionCount;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    #[test]
    fn should_serialize_get_transaction_count_params_as_tuple() {
        let params = GetTransactionCountParams {
            address: Address::from_str("0x407d73d8a49eeb85d32cf465507dd71d507100c1").unwrap(),
            block: BlockSpec::Tag(BlockTag::Finalized),
        };
        let serialized_params = serde_json::to_string(&params).unwrap();
        assert_eq!(
            serialized_params,
            r#"["0x407d73d8a49eeb85d32cf465507dd71d507100c1","finalized"]"#
        );
    }

    #[test]
    fn should_deserialize_transaction_count() {
        let count: TransactionCount = serde_json::from_str("\"0x3d8\"").unwrap();
        assert_eq!(count, TransactionCount::from(0x3d8_u32));
    }
}
