use crate::*;

pub fn get_request_cost(
    source: &ResolvedSource,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> u128 {
    let (http_cost, provider_cost) =
        get_request_costs(source, json_rpc_payload, max_response_bytes);
    http_cost + provider_cost
}

pub fn get_request_costs(
    source: &ResolvedSource,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> (u128, u128) {
    match source {
        ResolvedSource::Url(s) => (
            get_http_request_cost(s, json_rpc_payload, max_response_bytes),
            0,
        ),
        ResolvedSource::Provider(p) => (
            get_http_request_cost(&p.service_url(), json_rpc_payload, max_response_bytes),
            get_provider_cost(p, json_rpc_payload),
        ),
    }
}

/// Calculate the baseline cost of sending a JSON-RPC request using HTTP outcalls.
pub fn get_http_request_cost(
    service_url: &str,
    json_rpc_payload: &str,
    max_response_bytes: u64,
) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let ingress_bytes =
        (json_rpc_payload.len() + service_url.len()) as u128 + INGRESS_OVERHEAD_BYTES;
    let base_cost = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_COST
        + HTTP_OUTCALL_BYTE_RECEIEVED_COST * (ingress_bytes + max_response_bytes as u128);
    base_cost * (nodes_in_subnet as u128) / BASE_SUBNET_SIZE
}

/// Calculate the additional cost for calling a registered JSON-RPC provider.
pub fn get_provider_cost(provider: &Provider, json_rpc_payload: &str) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let cost_per_node = provider.cycles_per_call as u128
        + provider.cycles_per_message_byte as u128 * json_rpc_payload.len() as u128;
    cost_per_node * (nodes_in_subnet as u128)
}

#[test]
fn test_request_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = get_request_cost(
        &ResolvedSource::Url("https://cloudflare-eth.com".to_string()),
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        1000,
    );
    let s10 = "0123456789";
    let base_cost_s10 = get_request_cost(
        &ResolvedSource::Url("https://cloudflare-eth.com".to_string()),
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        1000,
    );
    assert_eq!(
        base_cost + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_BYTE_RECEIEVED_COST),
        base_cost_s10
    )
}

#[test]
fn test_provider_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let provider = Provider {
        provider_id: 0,
        base_url: "".to_string(),
        credential_path: "".to_string(),
        owner: Principal::anonymous(),
        chain_id: 1,
        cycles_owed: 0,
        cycles_per_call: 0,
        cycles_per_message_byte: 2,
    };
    let base_cost = get_provider_cost(
        &provider,
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
    );

    let provider_s10 = Provider {
        provider_id: 0,
        base_url: "".to_string(),
        credential_path: "".to_string(),
        owner: Principal::anonymous(),
        chain_id: 1,
        cycles_owed: 0,
        cycles_per_call: 1000,
        cycles_per_message_byte: 2,
    };
    let s10 = "0123456789";
    let base_cost_s10 = get_provider_cost(
        &provider_s10,
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
    );
    assert_eq!(base_cost + (10 * 2 + 1000) * 13, base_cost_s10)
}
