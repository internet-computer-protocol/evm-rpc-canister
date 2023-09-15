use ic_eth::core::types::{RecoveryMessage, Signature};

pub fn do_verify_signature(eth_address: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let eth_address_bytes: [u8; 20] = eth_address
        .try_into()
        .unwrap_or_else(|_| ic_cdk::trap("expected 20-byte address"));
    if signature.len() != 65 {
        ic_cdk::trap("expected 65-byte signature");
    }
    Signature {
        r: signature[..32].into(),
        s: signature[32..64].into(),
        v: signature[64].into(),
    }
    .verify(RecoveryMessage::Data(message), eth_address_bytes)
    .is_ok()
}

#[test]
fn test_verify_signature() {
    // TODO
}
