//! Types used for JSON-RPC requests and responses with Ethereum JSON-RPC providers.

use crate::rpc_client::eth_rpc::HttpResponsePayload;
use candid::Deserialize;
use serde::Serialize;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

pub mod requests;
pub mod responses;

macro_rules! bytes_array {
    ($name: ident, $size: expr) => {
        #[doc = concat!("Ethereum byte array (hex representation is prefixed by 0x) wrapping a `[u8; ", stringify!($size), "]`. ")]
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "ic_ethereum_types::serde_data")] [u8; $size]);

        impl $name {
            pub fn new(value: [u8; $size]) -> Self {
                Self(value)
            }

            pub fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if !s.starts_with("0x") {
                    return Err("Ethereum hex string doesn't start with 0x".to_string());
                }
                let mut bytes = [0u8; $size];
                hex::decode_to_slice(&s[2..], &mut bytes)
                    .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
                Ok(Self(bytes))
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:x}", self)
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:x}", self)
            }
        }

        impl LowerHex for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }

        impl UpperHex for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "0x{}", hex::encode_upper(self.0))
            }
        }
    };
}

bytes_array!(FixedSizeData, 32);
bytes_array!(Hash, 32);

impl HttpResponsePayload for Hash {}
