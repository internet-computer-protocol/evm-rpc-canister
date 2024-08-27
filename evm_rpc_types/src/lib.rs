#[cfg(test)]
mod tests;

use candid::types::{Serializer, Type};
use candid::{CandidType, Nat};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::str::FromStr;

mod request;
mod response;

pub use request::{FeeHistoryArgs, GetLogsArgs};
pub use response::{FeeHistory, LogEntry};

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "candid::Nat", into = "candid::Nat")]
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

    pub fn from_be_bytes(value: [u8; 32]) -> Self {
        Self::try_from(Nat::from(BigUint::from_bytes_be(&value)))
            .expect("BUG: Nat should fit in a U256")
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

impl From<Nat256> for Nat {
    fn from(value: Nat256) -> Self {
        value.0
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

macro_rules! impl_hex_string {
    ($name: ident($data: ty)) => {
        #[doc = concat!("Ethereum hex-string (String representation is prefixed by 0x) wrapping a `", stringify!($data), "`. ")]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name($data);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str("0x")?;
                f.write_str(&hex::encode(&self.0))
            }
        }

        impl From<$data> for $name {
            fn from(value: $data) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $data {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl CandidType for $name {
            fn _ty() -> Type {
                String::_ty()
            }

            fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_text(&self.to_string())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if !s.starts_with("0x") {
                    return Err("Ethereum hex string doesn't start with 0x".to_string());
                }
                hex::FromHex::from_hex(&s[2..])
                    .map(Self)
                    .map_err(|e| format!("Invalid Ethereum hex string: {}", e))
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.to_string()
            }
        }
    };
}

impl_hex_string!(Hex20([u8; 20]));
impl_hex_string!(Hex32([u8; 32]));
impl_hex_string!(Hex(Vec<u8>));