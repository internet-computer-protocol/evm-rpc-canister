use candid::Principal;

pub fn to_principal(principal: &str) -> Principal {
    match Principal::from_text(principal) {
        Ok(p) => p,
        Err(e) => ic_cdk::trap(&format!("failed to convert Principal {principal} {e:?}",)),
    }
}
