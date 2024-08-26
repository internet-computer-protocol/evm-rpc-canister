use crate::Nat256;
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, CandidType)]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    #[serde(rename = "oldestBlock")]
    pub oldest_block: Nat256,

    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: Vec<Nat256>,

    /// An array of block gas used ratios (gasUsed / gasLimit).
    #[serde(rename = "gasUsedRatio")]
    pub gas_used_ratio: Vec<f64>,

    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    #[serde(rename = "reward")]
    pub reward: Vec<Vec<Nat256>>,
}
