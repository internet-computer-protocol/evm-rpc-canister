use candid::candid_method;
use ic_cdk_macros::update;

#[update]
#[candid_method(update)]
pub fn test() {}
