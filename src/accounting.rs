use cketh_common::eth_rpc_client::providers::RpcApi;

use crate::{
    constants::{
        CANISTER_OVERHEAD, COLLATERAL_CYCLES_PER_NODE, HTTP_OUTCALL_REQUEST_BASE_COST,
        HTTP_OUTCALL_REQUEST_COST_PER_BYTE, HTTP_OUTCALL_REQUEST_PER_NODE_COST,
        HTTP_OUTCALL_RESPONSE_COST_PER_BYTE, INGRESS_MESSAGE_BYTE_RECEIVED_COST,
        INGRESS_MESSAGE_RECEIVED_COST, INGRESS_OVERHEAD_BYTES, RPC_URL_MIN_COST_BYTES,
    },
    memory::get_nodes_in_subnet,
    types::{Provider, ResolvedRpcService},
};

/// Returns the cycles cost of an RPC request.
pub fn get_rpc_cost(
    service: &ResolvedRpcService,
    payload_size_bytes: u64,
    max_response_bytes: u64,
) -> u128 {
    match service {
        ResolvedRpcService::Api(api) => {
            get_http_request_cost(api, payload_size_bytes, max_response_bytes)
        }
        ResolvedRpcService::Provider(provider) => {
            let http_cost =
                get_http_request_cost(&provider.api(), payload_size_bytes, max_response_bytes);
            let provider_cost = get_provider_cost(provider, payload_size_bytes);
            http_cost + provider_cost
        }
    }
}

/// Calculates the baseline cost of sending a JSON-RPC request using HTTP outcalls.
pub fn get_http_request_cost(
    api: &RpcApi,
    payload_size_bytes: u64,
    max_response_bytes: u64,
) -> u128 {
    let nodes_in_subnet = get_nodes_in_subnet();
    let ingress_bytes = payload_size_bytes as u128
        + u32::max(RPC_URL_MIN_COST_BYTES, api.url.len() as u32) as u128
        + INGRESS_OVERHEAD_BYTES;
    let cost_per_node = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_BASE_COST
        + HTTP_OUTCALL_REQUEST_PER_NODE_COST * nodes_in_subnet as u128
        + HTTP_OUTCALL_REQUEST_COST_PER_BYTE * payload_size_bytes as u128
        + HTTP_OUTCALL_RESPONSE_COST_PER_BYTE * max_response_bytes as u128
        + CANISTER_OVERHEAD;
    cost_per_node * (nodes_in_subnet as u128)
}

/// Calculate the additional cost for calling a registered JSON-RPC provider.
pub fn get_provider_cost(provider: &Provider, payload_size_bytes: u64) -> u128 {
    let nodes_in_subnet = get_nodes_in_subnet();
    let cost_per_node = provider.cycles_per_call as u128
        + provider.cycles_per_message_byte as u128 * payload_size_bytes as u128;
    cost_per_node * (nodes_in_subnet as u128)
}

/// Calculate the cost + collateral cycles for an HTTP request.
pub fn get_cost_with_collateral(cycles_cost: u128) -> u128 {
    cycles_cost + COLLATERAL_CYCLES_PER_NODE * get_nodes_in_subnet() as u128
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        accounting::{get_provider_cost, get_rpc_cost},
        constants::{NODES_IN_FIDUCIARY_SUBNET, NODES_IN_STANDARD_SUBNET},
        memory::{set_nodes_in_subnet, PROVIDERS},
        providers::do_register_provider,
        types::{Provider, RegisterProviderArgs, ResolvedRpcService},
    };
    use candid::Principal;

    #[test]
    fn test_request_cost() {
        for nodes_in_subnet in [1, NODES_IN_STANDARD_SUBNET, NODES_IN_FIDUCIARY_SUBNET] {
            println!("Nodes in subnet: {nodes_in_subnet}");

            set_nodes_in_subnet(nodes_in_subnet);

            let url = "https://cloudflare-eth.com";
            let payload =
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}";
            let base_cost = get_rpc_cost(
                &ResolvedRpcService::Api(RpcApi {
                    url: url.to_string(),
                    headers: None,
                }),
                payload.len() as u64,
                1000,
            );
            let base_cost_10_extra_bytes = get_rpc_cost(
                &ResolvedRpcService::Api(RpcApi {
                    url: url.to_string(),
                    headers: None,
                }),
                payload.len() as u64 + 10,
                1000,
            );
            let estimated_cost_10_extra_bytes = base_cost
                + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_REQUEST_COST_PER_BYTE)
                    * nodes_in_subnet as u128;
            assert_eq!(base_cost_10_extra_bytes, estimated_cost_10_extra_bytes,);
        }
    }

    #[test]
    fn test_provider_cost() {
        for nodes_in_subnet in [1, NODES_IN_STANDARD_SUBNET, NODES_IN_FIDUCIARY_SUBNET] {
            println!("Nodes in subnet: {nodes_in_subnet}");

            set_nodes_in_subnet(nodes_in_subnet);

            let provider = Provider {
                provider_id: 0,
                hostname: "".to_string(),
                credential_path: "".to_string(),
                credential_headers: vec![],
                owner: Principal::anonymous(),
                chain_id: 1,
                cycles_owed: 0,
                cycles_per_call: 0,
                cycles_per_message_byte: 2,
                primary: false,
            };
            let base_cost = get_provider_cost(
                &provider,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".len()
                    as u64,
            );

            let provider_10_extra_bytes = Provider {
                provider_id: 0,
                hostname: "".to_string(),
                credential_path: "".to_string(),
                credential_headers: vec![],
                owner: Principal::anonymous(),
                chain_id: 1,
                cycles_owed: 0,
                cycles_per_call: 1000,
                cycles_per_message_byte: 2,
                primary: false,
            };
            let base_cost_10_extra_bytes = get_provider_cost(
                &provider_10_extra_bytes,
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".len()
                    as u64
                    + 10,
            );
            assert_eq!(
                base_cost + (10 * 2 + 1000) * nodes_in_subnet as u128,
                base_cost_10_extra_bytes
            )
        }
    }

    #[test]
    fn test_candid_rpc_cost() {
        let provider_id = do_register_provider(
            Principal::anonymous(),
            RegisterProviderArgs {
                chain_id: 0,
                hostname: "rpc.example.com".to_string(),
                credential_headers: None,
                credential_path: "".to_string(),
                cycles_per_call: 999,
                cycles_per_message_byte: 1000,
            },
        );
        let service = ResolvedRpcService::Provider(
            PROVIDERS.with(|providers| providers.borrow().get(&provider_id).unwrap()),
        );

        // 13-node subnet
        set_nodes_in_subnet(NODES_IN_STANDARD_SUBNET);
        assert_eq!(
            [
                get_rpc_cost(&service, 0, 0),
                get_rpc_cost(&service, 123, 123),
                get_rpc_cost(&service, 123, 4567890),
                get_rpc_cost(&service, 890, 4567890),
            ],
            [87008987, 93724787, 47598501587, 47632402987]
        );

        // Fiduciary subnet
        set_nodes_in_subnet(NODES_IN_FIDUCIARY_SUBNET);
        assert_eq!(
            [
                get_rpc_cost(&service, 0, 0),
                get_rpc_cost(&service, 123, 123),
                get_rpc_cost(&service, 123, 4567890),
                get_rpc_cost(&service, 890, 4567890),
            ],
            [212603972, 227068772, 102545049572, 102618067972]
        );
    }
}
