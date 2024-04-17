# Bazel workspace

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

git_repository(
    name="ic",
    remote="https://github.com/dfinity/ic.git",
    commit="ca5e5052886de781021506814d2c6502e375da48",
)

http_archive(
    name = "rules_rust",
    integrity = "sha256-XT1YVJ6FHJTXBr1v3px2fV37/OCS3dQk3ul+XvfIIf8=",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.42.0/rules_rust-v0.42.0.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")
load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")
load("@rules_rust//crate_universe:defs.bzl", "crates_repository")

rules_rust_dependencies()
rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.76.0",
    ],
)
crate_universe_dependencies()
crates_repository(
    name = "crate_index",
    cargo_lockfile = "//:Cargo.lock",
    lockfile = "//:cargo-bazel-lock.json",
    manifests = [
        "//:Cargo.toml",
        "//:e2e/rust/Cargo.toml",
    ],
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()
