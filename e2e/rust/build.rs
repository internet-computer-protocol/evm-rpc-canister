use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();

    builder.add({
        let mut config = Config::new("EVM_RPC_STAGING_FIDUCIARY");
        config.binding.type_attributes =
            "#[derive(CandidType, Clone, Debug, Deserialize)]".to_string();
        config
    });

    builder.build(None);
}
