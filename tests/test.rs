use ic_eth_rpc::*;

#[test]
fn check_candid_interface() {
    use candid::utils::{service_compatible, CandidSource};
    use std::path::Path;

    candid::export_service!();
    let new_interface = __export_service();

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(Path::new("candid/ic_eth.did")),
    )
    .unwrap();
}

#[test]
fn check_json_rpc_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = get_cycles_cost(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        "https://cloudflare-eth.com",
        1000,
    );
    let s10 = "0123456789";
    let base_cost_s10 = get_cycles_cost(
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
fn check_json_rpc_provider_cycles_cost() {
    METADATA.with(|m| {
        let mut metadata = m.borrow().get().clone();
        metadata.nodes_in_subnet = 13;
        m.borrow_mut().set(metadata).unwrap();
    });

    let base_cost = get_provider_cycles_cost(
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}",
        0,
        2,
    );
    let s10 = "0123456789";
    let base_cost_s10 = get_provider_cycles_cost(
        &("{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":[],\"id\":1}".to_string()
            + s10),
        1000,
        2,
    );
    assert_eq!(base_cost + (10 * 2 + 1000) * 13, base_cost_s10)
}

#[test]
fn check_authorization() {
    let principal1 =
        Principal::from_text("k5dlc-ijshq-lsyre-qvvpq-2bnxr-pb26c-ag3sc-t6zo5-rdavy-recje-zqe")
            .unwrap();
    let principal2 =
        Principal::from_text("yxhtl-jlpgx-wqnzc-ysego-h6yqe-3zwfo-o3grn-gvuhm-nz3kv-ainub-6ae")
            .unwrap();
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
    do_authorize(principal1, Auth::Rpc);
    assert!(is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
    do_deauthorize(principal1, Auth::Rpc);
    assert!(!is_authorized_principal(&principal1, Auth::Rpc));
    assert!(!is_authorized_principal(&principal2, Auth::Rpc));
}
