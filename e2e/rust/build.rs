use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();

    let mut evm_rpc = Config::new("evm_rpc");
    evm_rpc.binding.type_attributes =
        "#[derive(CandidType, Clone, Debug, Deserialize)]".to_string();
    builder.add(evm_rpc);

    builder.build(None);
}
