use candid::{CandidType, Nat};
use serde::Deserialize;

pub mod request;
pub mod response;

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize, Default)]
pub enum BlockTag {
    #[default]
    Latest,
    Finalized,
    Safe,
    Earliest,
    Pending,
    Number(Nat),
}
