# Bazel build configuration

load("@crate_index//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_library")
load("@ic//bazel:canisters.bzl", "rust_canister")

package(default_visibility = ["//visibility:public"])

rust_canister(
    name = "evm_rpc",
    srcs = glob([
        "src/**/*.rs",
    ]),
    crate_features = [],
    crate_name = "evm_rpc",
    service_file = "candid/evm_rpc.did",
    deps = all_crate_deps() + [
        ##### ":evm_rpc",
    ],
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
)
