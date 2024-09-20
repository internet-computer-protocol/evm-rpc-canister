mod eth_rpc_client {
    use crate::rpc_client::EthRpcClient;
    use evm_rpc_types::{EthMainnetService, ProviderError, RpcService, RpcServices};
    use maplit::btreeset;

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
            &btreeset! {
                RpcService::EthMainnet(provider1),
                RpcService::EthMainnet(provider2)
            }
        );
    }
}

mod multi_call_results {
    use evm_rpc_types::{EthMainnetService, RpcService};

    const ANKR: RpcService = RpcService::EthMainnet(EthMainnetService::Ankr);
    const PUBLIC_NODE: RpcService = RpcService::EthMainnet(EthMainnetService::PublicNode);
    const CLOUDFLARE: RpcService = RpcService::EthMainnet(EthMainnetService::Cloudflare);

    mod reduce_with_equality {
        use crate::rpc_client::json::responses::JsonRpcResult;
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
        use crate::rpc_client::json::responses::FeeHistory;
        use crate::rpc_client::json::responses::JsonRpcResult;
        use crate::rpc_client::numeric::{BlockNumber, WeiPerGas};
        use crate::rpc_client::tests::multi_call_results::{ANKR, CLOUDFLARE, PUBLIC_NODE};
        use crate::rpc_client::{MultiCallError, MultiCallResults};

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
    use crate::rpc_client::json::responses::{TransactionReceipt, TransactionStatus};
    use crate::rpc_client::json::Hash;
    use crate::rpc_client::numeric::{BlockNumber, GasAmount, WeiPerGas};
    use assert_matches::assert_matches;
    use proptest::proptest;
    use std::str::FromStr;

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

mod providers {
    use crate::arbitrary::{arb_custom_rpc_services, arb_rpc_services};
    use crate::rpc_client::Providers;
    use assert_matches::assert_matches;
    use evm_rpc_types::{
        ConsensusStrategy, EthMainnetService, EthSepoliaService, L2MainnetService, ProviderError,
        RpcService, RpcServices,
    };
    use maplit::btreeset;
    use proptest::arbitrary::any;
    use proptest::proptest;
    use std::collections::BTreeSet;
    use std::fmt::Debug;

    #[test]
    fn should_partition_providers_between_default_and_non_default() {
        fn assert_is_partition<T: Debug + Ord>(left: &[T], right: &[T], all: &[T]) {
            let left_set = left.iter().collect::<BTreeSet<_>>();
            let right_set = right.iter().collect::<BTreeSet<_>>();
            let all_set = all.iter().collect::<BTreeSet<_>>();

            assert!(
                left_set.is_disjoint(&right_set),
                "Non-empty intersection {:?}",
                left_set.intersection(&right_set).collect::<Vec<_>>()
            );
            assert_eq!(
                left_set.union(&right_set).copied().collect::<BTreeSet<_>>(),
                all_set
            );
        }

        assert_is_partition(
            &Providers::DEFAULT_ETH_MAINNET_SERVICES,
            &Providers::NON_DEFAULT_ETH_MAINNET_SERVICES,
            &EthMainnetService::all(),
        );
        assert_is_partition(
            &Providers::DEFAULT_ETH_SEPOLIA_SERVICES,
            &Providers::NON_DEFAULT_ETH_SEPOLIA_SERVICES,
            &EthSepoliaService::all(),
        );
        assert_is_partition(
            &Providers::DEFAULT_L2_MAINNET_SERVICES,
            &Providers::NON_DEFAULT_L2_MAINNET_SERVICES,
            &L2MainnetService::all(),
        )
    }

    proptest! {
        #[test]
        fn should_choose_custom_providers(
            not_enough_custom_providers in arb_custom_rpc_services(0..=3),
            custom_providers in arb_custom_rpc_services(4..=4),
            too_many_custom_providers in arb_custom_rpc_services(5..=10)
        ) {
            let strategy = ConsensusStrategy::Threshold {
                num_providers: Some(4),
                min_num_ok: 3,
            };

            let providers = Providers::new(
                not_enough_custom_providers,
                strategy.clone(),
            );
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));

             let providers = Providers::new(
                too_many_custom_providers,
                strategy.clone(),
            );
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));

            let _providers = Providers::new(
                custom_providers.clone(),
                strategy,
            ).unwrap();
        }
    }

    #[test]
    fn should_choose_default_providers_first() {
        let strategy = ConsensusStrategy::Threshold {
            num_providers: Some(4),
            min_num_ok: 3,
        };

        let providers = Providers::new(RpcServices::EthMainnet(None), strategy.clone()).unwrap();
        assert_eq!(
            providers.services,
            btreeset! {
                Providers::DEFAULT_ETH_MAINNET_SERVICES[0],
                Providers::DEFAULT_ETH_MAINNET_SERVICES[1],
                Providers::DEFAULT_ETH_MAINNET_SERVICES[2],
                EthMainnetService::Alchemy,
            }
            .into_iter()
            .map(RpcService::EthMainnet)
            .collect()
        );

        let providers = Providers::new(RpcServices::EthSepolia(None), strategy.clone()).unwrap();
        assert_eq!(
            providers.services,
            btreeset! {
                Providers::DEFAULT_ETH_SEPOLIA_SERVICES[0],
                Providers::DEFAULT_ETH_SEPOLIA_SERVICES[1],
                Providers::DEFAULT_ETH_SEPOLIA_SERVICES[2],
                EthSepoliaService::Alchemy,
            }
            .into_iter()
            .map(RpcService::EthSepolia)
            .collect()
        );

        let providers = Providers::new(RpcServices::ArbitrumOne(None), strategy.clone()).unwrap();
        assert_eq!(
            providers.services,
            btreeset! {
                Providers::DEFAULT_L2_MAINNET_SERVICES[0],
                Providers::DEFAULT_L2_MAINNET_SERVICES[1],
                Providers::DEFAULT_L2_MAINNET_SERVICES[2],
                L2MainnetService::Alchemy,
            }
            .into_iter()
            .map(RpcService::ArbitrumOne)
            .collect()
        );
    }

    #[test]
    fn should_fail_when_threshold_unspecified_with_default_providers() {
        let strategy = ConsensusStrategy::Threshold {
            num_providers: None,
            min_num_ok: 3,
        };

        for default_services in [
            RpcServices::EthMainnet(None),
            RpcServices::EthSepolia(None),
            RpcServices::ArbitrumOne(None),
            RpcServices::BaseMainnet(None),
            RpcServices::OptimismMainnet(None),
        ] {
            let providers = Providers::new(default_services, strategy.clone());
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_threshold_larger_than_number_of_supported_providers(min_num_ok in any::<u8>()) {
            for (default_services, max_num_providers) in [
                (
                    RpcServices::EthMainnet(None),
                    EthMainnetService::all().len(),
                ),
                (
                    RpcServices::EthSepolia(None),
                    EthSepoliaService::all().len(),
                ),
                (
                    RpcServices::ArbitrumOne(None),
                    L2MainnetService::all().len(),
                ),
                (
                    RpcServices::BaseMainnet(None),
                    L2MainnetService::all().len(),
                ),
                (
                    RpcServices::OptimismMainnet(None),
                    L2MainnetService::all().len(),
                ),
            ] {
                let strategy = ConsensusStrategy::Threshold {
                    num_providers: Some((max_num_providers + 1) as u8),
                    min_num_ok,
                };
                let providers = Providers::new(default_services, strategy);
                assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
            }
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_threshold_invalid(services in arb_rpc_services()) {
            let strategy = ConsensusStrategy::Threshold {
                num_providers: Some(4),
                min_num_ok: 5,
            };

            let providers = Providers::new(services, strategy.clone());
            assert_matches!(providers, Err(ProviderError::InvalidRpcConfig(_)));
        }
    }
}
