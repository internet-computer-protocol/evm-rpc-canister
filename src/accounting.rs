use crate::constants::{
    CANISTER_OVERHEAD, COLLATERAL_CYCLES_PER_NODE, HTTP_OUTCALL_REQUEST_BASE_COST,
    HTTP_OUTCALL_REQUEST_COST_PER_BYTE, HTTP_OUTCALL_REQUEST_PER_NODE_COST,
    HTTP_OUTCALL_RESPONSE_COST_PER_BYTE, INGRESS_MESSAGE_BYTE_RECEIVED_COST,
    INGRESS_MESSAGE_RECEIVED_COST, INGRESS_OVERHEAD_BYTES, NODES_IN_SUBNET, RPC_URL_COST_BYTES,
};

/// Calculates the cost of sending a JSON-RPC request using HTTP outcalls.
pub fn get_http_request_cost(payload_size_bytes: u64, max_response_bytes: u64) -> u128 {
    let nodes_in_subnet = NODES_IN_SUBNET as u128;
    let ingress_bytes =
        payload_size_bytes as u128 + RPC_URL_COST_BYTES as u128 + INGRESS_OVERHEAD_BYTES;
    let cost_per_node = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_BASE_COST
        + HTTP_OUTCALL_REQUEST_PER_NODE_COST * nodes_in_subnet
        + HTTP_OUTCALL_REQUEST_COST_PER_BYTE * payload_size_bytes as u128
        + HTTP_OUTCALL_RESPONSE_COST_PER_BYTE * max_response_bytes as u128
        + CANISTER_OVERHEAD;
    cost_per_node * nodes_in_subnet
}

/// Calculate the cost + collateral cycles for an HTTP request.
pub fn get_cost_with_collateral(cycles_cost: u128) -> u128 {
    cycles_cost + COLLATERAL_CYCLES_PER_NODE * NODES_IN_SUBNET as u128
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{accounting::get_http_request_cost, constants::NODES_IN_SUBNET};

    #[test]
    fn test_request_cost() {
        let payload = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}";
        let base_cost = get_http_request_cost(payload.len() as u64, 1000);
        let base_cost_10_extra_bytes = get_http_request_cost(payload.len() as u64 + 10, 1000);
        let estimated_cost_10_extra_bytes = base_cost
            + 10 * (INGRESS_MESSAGE_BYTE_RECEIVED_COST + HTTP_OUTCALL_REQUEST_COST_PER_BYTE)
                * NODES_IN_SUBNET as u128;
        assert_eq!(base_cost_10_extra_bytes, estimated_cost_10_extra_bytes);
    }

    #[test]
    fn test_candid_rpc_cost() {
        assert_eq!(
            [
                get_http_request_cost(0, 0),
                get_http_request_cost(123, 123),
                get_http_request_cost(123, 4567890),
                get_http_request_cost(890, 4567890),
            ],
            [240932000, 253133600, 113533755200, 113590820000]
        );
    }
}
