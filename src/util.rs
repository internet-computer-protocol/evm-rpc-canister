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
    // match &mut json {
    //     Value::Object(ref mut obj) => {
    //         obj.insert("canonical".to_string(), Value::Bool(true));
    //     }
    //     _ => (),
    // };
    serde_json::to_vec(&json).ok()
}
