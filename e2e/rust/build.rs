use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();

    builder.add({
        let mut config = Config::new("evm_rpc_staging_fiduciary");
        config.binding.type_attributes =
            "#[derive(CandidType, Clone, Debug, Deserialize)]".to_string();
        config
    });

    builder.build(None);
}
