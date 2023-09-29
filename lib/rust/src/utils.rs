pub fn to_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

pub fn from_hex(data: &str) -> Option<Vec<u8>> {
    if !data.starts_with("0x") {
        return None;
    }
    hex::decode(&data[2..]).ok()
}
