use evm_rpc_types::Nat256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;

/// `CheckedAmountOf<Unit>` provides a type-safe way to keep an amount of some `Unit`.
/// In contrast to `AmountOf<Unit>`, all operations are checked and do not overflow.
pub struct CheckedAmountOf<Unit>(ethnum::u256, PhantomData<Unit>);

impl<Unit> CheckedAmountOf<Unit> {
    pub const ZERO: Self = Self(ethnum::u256::ZERO, PhantomData);
    pub const ONE: Self = Self(ethnum::u256::ONE, PhantomData);
    pub const TWO: Self = Self(ethnum::u256::new(2), PhantomData);
    pub const MAX: Self = Self(ethnum::u256::MAX, PhantomData);

    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants.
    #[inline]
    pub const fn new(value: u128) -> CheckedAmountOf<Unit> {
        Self(ethnum::u256::new(value), PhantomData)
    }

    #[inline]
    const fn from_inner(value: ethnum::u256) -> Self {
        Self(value, PhantomData)
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self::from_inner(ethnum::u256::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Returns the display implementation of the inner value.
    /// Useful to avoid thousands of separators if value is used for example in URLs.
    /// ```
    /// use evm_rpc::rpc_client::checked_amount::CheckedAmountOf;
    ///
    /// enum MetricApple{}
    /// type Apples = CheckedAmountOf<MetricApple>;
    /// let many_apples = Apples::from(4_332_415_u32);
    ///
    /// assert_eq!(many_apples.to_string_inner(), "4332415".to_string());
    /// ```
    pub fn to_string_inner(&self) -> String {
        self.0.to_string()
    }
}

macro_rules! impl_from {
    ($($t:ty),* $(,)?) => {$(
        impl<Unit> From<$t> for CheckedAmountOf<Unit> {
            #[inline]
            fn from(value: $t) -> Self {
                Self(ethnum::u256::from(value), PhantomData)
            }
        }
    )*};
}

impl_from! { u8, u16, u32, u64, u128 }

impl<Unit> From<Nat256> for CheckedAmountOf<Unit> {
    fn from(value: Nat256) -> Self {
        Self::from_be_bytes(value.into_be_bytes())
    }
}

impl<Unit> From<CheckedAmountOf<Unit>> for Nat256 {
    fn from(value: CheckedAmountOf<Unit>) -> Self {
        Nat256::from_be_bytes(value.to_be_bytes())
    }
}

impl<Unit> fmt::Debug for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::Display for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::LowerHex for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<Unit> fmt::UpperHex for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl<Unit> Clone for CheckedAmountOf<Unit> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Unit> Copy for CheckedAmountOf<Unit> {}

impl<Unit> PartialEq for CheckedAmountOf<Unit> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Unit> Eq for CheckedAmountOf<Unit> {}

impl<Unit> PartialOrd for CheckedAmountOf<Unit> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl<Unit> Ord for CheckedAmountOf<Unit> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.cmp(&rhs.0)
    }
}

// Derived serde `impl Serialize` produces an extra `unit` value for
// phantom data, e.g. `AmountOf::<Meters>::from(10)` is serialized
// into json as `[10, null]` by default.
//
// We want serialization format of `Repr` and the `AmountOf` to match
// exactly, that's why we have to provide custom instances.
impl<Unit> Serialize for CheckedAmountOf<Unit> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Unit> Deserialize<'de> for CheckedAmountOf<Unit> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ethnum::u256::deserialize(deserializer).map(Self::from_inner)
    }
}
