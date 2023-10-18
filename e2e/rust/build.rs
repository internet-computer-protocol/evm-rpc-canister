use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();

    let mut eth_rpc = Config::new("eth_rpc");
    eth_rpc.binding.type_attributes =
        "#[derive(CandidType, Clone, Debug, Deserialize)]".to_string();
    builder.add(eth_rpc);

    builder.build(None);
}
