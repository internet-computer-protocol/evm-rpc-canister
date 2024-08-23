#[cfg(test)]
mod tests;

use candid::types::{Serializer, Type};
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
    Number(Nat256),
}

/// A `Nat` that is guaranteed to fit in 256 bits.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "candid::Nat")]
pub struct Nat256(Nat);

impl Nat256 {
    pub fn into_be_bytes(self) -> [u8; 32] {
        let value_bytes = self.0 .0.to_bytes_be();
        let mut value_u256 = [0u8; 32];
        assert!(
            value_bytes.len() <= 32,
            "BUG: Nat does not fit in a U256: {:?}",
            self.0
        );
        value_u256[32 - value_bytes.len()..].copy_from_slice(&value_bytes);
        value_u256
    }
}

impl AsRef<Nat> for Nat256 {
    fn as_ref(&self) -> &Nat {
        &self.0
    }
}

impl CandidType for Nat256 {
    fn _ty() -> Type {
        Nat::_ty()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_nat(self.as_ref())
    }
}

impl TryFrom<Nat> for Nat256 {
    type Error = String;

    fn try_from(value: Nat) -> Result<Self, Self::Error> {
        if value.0.to_bytes_le().len() > 32 {
            Err("Nat does not fit in a U256".to_string())
        } else {
            Ok(Nat256(value))
        }
    }
}

macro_rules! impl_from_unchecked {
    ($f: ty, $($t: ty)*) => ($(
        impl From<$t> for $f {
            #[inline]
            fn from(v: $t) -> Self { Self::try_from(Nat::from(v)).unwrap() }
        }
    )*)
}
// all the types below are guaranteed to fit in 256 bits
impl_from_unchecked!( Nat256, usize u8 u16 u32 u64 u128 );
