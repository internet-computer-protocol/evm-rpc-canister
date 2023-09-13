use crate::*;

pub fn get_cycles_cost(json_rpc_payload: &str, service_url: &str, max_response_bytes: u64) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let ingress_bytes =
        (json_rpc_payload.len() + service_url.len()) as u128 + INGRESS_OVERHEAD_BYTES;
    let base_cost = INGRESS_MESSAGE_RECEIVED_COST
        + INGRESS_MESSAGE_BYTE_RECEIVED_COST * ingress_bytes
        + HTTP_OUTCALL_REQUEST_COST
        + HTTP_OUTCALL_BYTE_RECEIEVED_COST * (ingress_bytes + max_response_bytes as u128);
    base_cost * (nodes_in_subnet as u128) / BASE_SUBNET_SIZE
}

pub fn get_provider_cycles_cost(
    json_rpc_payload: &str,
    provider_cycles_per_call: u64,
    provider_cycles_per_message_byte: u64,
) -> u128 {
    let nodes_in_subnet = METADATA.with(|m| m.borrow().get().nodes_in_subnet);
    let base_cost = provider_cycles_per_call as u128
        + provider_cycles_per_message_byte as u128 * json_rpc_payload.len() as u128;
    base_cost * (nodes_in_subnet as u128)
}
