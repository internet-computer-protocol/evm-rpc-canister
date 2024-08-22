use candid::{CandidType, Nat};

#[derive(Debug, Clone, PartialEq, CandidType)]
pub struct FeeHistory {
    /// Lowest number block of the returned range.
    pub oldest_block: Nat,
    /// An array of block base fees per gas.
    /// This includes the next block after the newest of the returned range,
    /// because this value can be derived from the newest block.
    /// Zeroes are returned for pre-EIP-1559 blocks.
    pub base_fee_per_gas: Vec<Nat>,
    /// An array of block gas used ratios (gasUsed / gasLimit).
    pub gas_used_ratio: Vec<f64>,
    /// A two-dimensional array of effective priority fees per gas at the requested block percentiles.
    pub reward: Vec<Vec<Nat>>,
}
