use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();

    builder.add({
        // Uppercase canister name is a workaround for using `ic-cdk-bindgen` with `dfx` >= 0.18.0
        let mut config = Config::new("EVM_RPC_STAGING");
        config
            .binding
            .set_type_attributes("#[derive(CandidType, Clone, Debug, Deserialize)]".to_string());
        config
    });

    builder.build(None);
}
