use serde_json::Value;

pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.starts_with("0x") {
        return None;
    }
    hex::decode(&hex[2..]).ok()
}

pub fn canonicalize_json(text: &[u8]) -> Option<Vec<u8>> {
    let json = serde_json::from_slice::<Value>(text).ok()?;
    serde_json::to_vec(&json).ok()
}

#[cfg(test)]
mod test {
    use crate::util::{canonicalize_json, hex_to_bytes};

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("aa"), None);
        assert_eq!(hex_to_bytes("0x"), Some(vec![]));
        assert_eq!(hex_to_bytes("0xAA"), Some(vec![0xAA]));
        assert_eq!(hex_to_bytes("0xaa"), Some(vec![0xAA]));
    }

    #[test]
    fn test_canonicalize_json() {
        assert_eq!(
            canonicalize_json(r#"{"A":1,"B":2}"#.as_bytes()).unwrap(),
            canonicalize_json(r#"{"B":2,"A":1}"#.as_bytes()).unwrap()
        );
    }
}
