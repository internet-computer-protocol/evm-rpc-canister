mod nat256 {
    use crate::Nat256;
    use candid::{Decode, Encode, Nat};
    use num_bigint::BigUint;
    use proptest::{arbitrary::any, prelude::Strategy, proptest};

    proptest! {
        #[test]
        fn should_encode_decode(u256 in arb_u256()) {
            encode_decode_roundtrip(u256);
        }

        #[test]
        fn should_fail_to_decode_nat_overflowing_a_u256(offset in any::<u64>()) {
            let u256_max: BigUint = BigUint::from_bytes_be(&[0xff; 32]);
            encode_decode_roundtrip(u256_max.clone());

            let offset = BigUint::from(offset);
            let overflow_u256 = Nat::from(u256_max + offset);
            let encoded_overflow_u256 = Encode!(&overflow_u256).unwrap();

            let decoded_overflow_nat256: Result<Nat256, _> = Decode!(&encoded_overflow_u256, Nat256);
            let error_msg = format!("{:?}", decoded_overflow_nat256.unwrap_err());

            assert!(
                error_msg.contains("Deserialize error: Nat does not fit in a U256"),
                "Unexpected error message: {}",
                error_msg
            );
        }

        #[test]
        fn should_convert_to_bytes_and_back(u256 in arb_u256()) {
            let value = Nat256::try_from(Nat::from(u256)).unwrap();
            let bytes = value.clone().into_be_bytes();

            let value_from_bytes = Nat256::from_be_bytes(bytes);

            assert_eq!(value, value_from_bytes);
        }
    }

    fn encode_decode_roundtrip(value: BigUint) {
        let nat = Nat::from(value);
        let encoded_nat = Encode!(&nat).unwrap();

        let nat256 = Nat256::try_from(nat.clone()).unwrap();
        let encoded_nat256 = Encode!(&nat256).unwrap();

        assert_eq!(encoded_nat, encoded_nat256);

        let decoded_nat256: Nat256 = Decode!(&encoded_nat, Nat256).unwrap();
        assert_eq!(decoded_nat256.0, nat);
    }

    fn arb_u256() -> impl Strategy<Value = BigUint> {
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(|value| BigUint::from_bytes_be(&value))
    }
}
