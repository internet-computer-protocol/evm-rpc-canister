use ic_cdk_bindgen::{Builder, Config};

fn main() {
    let mut builder = Builder::new();
    builder.add(Config::new("eth_rpc"));
    builder.build(None);
}
