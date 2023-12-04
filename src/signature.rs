use ic_eth::core::types::{RecoveryMessage, Signature};

use crate::hex_to_bytes;

pub fn do_verify_message_signature(
    eth_address: &str,
    message: RecoveryMessage,
    signature: &str,
) -> bool {
    let eth_address_bytes: [u8; 20] = hex_to_bytes(eth_address)
        .unwrap_or_else(|| ic_cdk::trap("invalid hex string for address"))
        .try_into()
        .unwrap_or_else(|_| ic_cdk::trap("expected 20-byte address"));
    let signature_bytes: [u8; 65] = hex_to_bytes(signature)
        .unwrap_or_else(|| ic_cdk::trap("invalid hex string for signature"))
        .try_into()
        .unwrap_or_else(|_| ic_cdk::trap("expected 65-byte signature"));
    Signature {
        r: signature_bytes[..32].into(),
        s: signature_bytes[32..64].into(),
        v: signature_bytes[64].into(),
    }
    .verify(message, eth_address_bytes)
    .is_ok()
}

#[test]
fn test_verify_signature() {
    let a1 = "0xc9b28dca7ea6c5e176a58ba9df53c30ba52c6642";
    let a2 = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";

    let m1 = RecoveryMessage::Data("hello".as_bytes().to_vec());
    let s1 = "0x5c0e32248c10f7125b32cae1de9988f2dab686031083302f85b0a82f78e9206516b272fb7641f3e8ab63cf9f3a9b9220b2d6ff2699dc34f0d000d7693ca1ea5e1c";

    let m2 = RecoveryMessage::Data("other".as_bytes().to_vec());
    let s2 = "0x27ae1f90fd65c86b07aae1287dba8715db7e429ff9bf700205cb8ac904c6ba071c8fb7c6f8b5e15338521fee95a452c6a688f1c6fec5eeddbfa680a2abf300341b";

    // Invalid address
    assert!(!do_verify_message_signature(a2, m1.clone(), s1));

    // Invalid message
    assert!(!do_verify_message_signature(a1, m2.clone(), s1));

    // Invalid signature
    assert!(!do_verify_message_signature(a1, m1.clone(), s2));

    // Valid signature
    assert!(do_verify_message_signature(a1, m1, s1));
    assert!(do_verify_message_signature(a1, m2, s2));
}
