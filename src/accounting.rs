use crate::*;

/// Calculate the baseline cost of sending a JSON-RPC request using HTTP outcalls.
pub fn get_request_cost(
    json_rpc_payload: &str,
    service_url: &str,
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
pub fn get_provider_cost(
    json_rpc_payload: &str,
    provider_cycles_per_call: u64,
    provider_cycles_per_message_byte: u64,
) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let cost_per_node = provider_cycles_per_call as u128
        + provider_cycles_per_message_byte as u128 * json_rpc_payload.len() as u128;
    cost_per_node * (nodes_in_subnet as u128)
}

#[test]
fn test_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = get_request_cost(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        "https://cloudflare-eth.com",
        1000,
    );
    let s10 = "0123456789";
    let base_cost_s10 = get_request_cost(
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        "https://cloudflare-eth.com",
        1000,
    );
    assert_eq!(
        base_cost + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_BYTE_RECEIEVED_COST),
        base_cost_s10
    )
}

#[test]
fn test_provider_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = get_provider_cost(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        0,
        2,
    );
    let s10 = "0123456789";
    let base_cost_s10 = get_provider_cost(
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        1000,
        2,
    );
    assert_eq!(base_cost + (10 * 2 + 1000) * 13, base_cost_s10)
}
