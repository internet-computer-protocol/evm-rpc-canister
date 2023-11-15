use candid::Principal;
use serde_json::Value;

pub fn to_principal(principal: &str) -> Principal {
    match Principal::from_text(principal) {
        Ok(p) => p,
        Err(e) => ic_cdk::trap(&format!("failed to convert Principal {principal} {e:?}",)),
    }
}

pub fn canonicalize_json(text: &[u8]) -> Option<Vec<u8>> {
    let json = serde_json::from_slice::<Value>(text).ok()?;
    serde_json::to_vec(&json).ok()
}

#[test]
fn test_canonicalize_json() {
    assert_eq!(
        canonicalize_json(r#"{"A":1,"B":2}"#.as_bytes()).unwrap(),
        canonicalize_json(r#"{"B":2,"A":1}"#.as_bytes()).unwrap()
    )
}
