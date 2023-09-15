use ic_eth::core::types::{Address, RecoveryMessage, Signature};

pub fn do_verify_signature(eth_address: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    if signature.len() != 65 {
        ic_cdk::trap("expected 65-byte signature");
    }
    Signature {
        r: signature[..32].into(),
        s: signature[32..64].into(),
        v: signature[64].into(),
    }
    .verify(
        RecoveryMessage::Data(message),
        Address::from_slice(&eth_address),
    )
    .is_ok()
}
