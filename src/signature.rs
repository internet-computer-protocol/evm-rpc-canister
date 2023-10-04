use ic_eth::core::types::{RecoveryMessage, Signature};

pub fn do_verify_signature(
    eth_address: &[u8],
    message: RecoveryMessage,
    signature: Vec<u8>,
) -> bool {
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
    .verify(message, eth_address_bytes)
    .is_ok()
}

#[test]
fn test_verify_signature() {
    let address = &hex::decode("c9b28dca7ea6c5e176a58ba9df53c30ba52c6642").unwrap();

    let m1 = RecoveryMessage::Data("hello".as_bytes().to_vec());
    let s1 = hex::decode("5c0e32248c10f7125b32cae1de9988f2dab686031083302f85b0a82f78e9206516b272fb7641f3e8ab63cf9f3a9b9220b2d6ff2699dc34f0d000d7693ca1ea5e1c").unwrap();

    let m2 = RecoveryMessage::Data("other".as_bytes().to_vec());
    let s2 = hex::decode("27ae1f90fd65c86b07aae1287dba8715db7e429ff9bf700205cb8ac904c6ba071c8fb7c6f8b5e15338521fee95a452c6a688f1c6fec5eeddbfa680a2abf300341b").unwrap();

    // Invalid message
    assert!(!do_verify_signature(address, m2.clone(), s1.clone()));

    // Invalid signature
    assert!(!do_verify_signature(address, m1.clone(), s2.clone()));

    // Valid signature
    assert!(do_verify_signature(address, m1, s1));
    assert!(do_verify_signature(address, m2, s2));
}
