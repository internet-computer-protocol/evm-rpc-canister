import EvmRpcCanister "canister:evm_rpc";

import Principal "mo:base/Principal";
import Evm "mo:evm";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Blob "mo:base/Blob";

actor class Main() {
    let mainnet = Evm.Rpc(
        #Canister EvmRpcCanister,
        #Service {
            hostname = "cloudflare-eth.com";
            network = ? #EthMainnet;
        },
    );

    public shared ({ caller }) func test() : async () {
        let source = #Service {
            hostname = "cloudflare-eth.com";
            chainId = ?(1 : Nat64); // Ethereum mainnet
        };
        let json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}";
        let maxResponseBytes : Nat64 = 1000;

        let cyclesResult = await EvmRpcCanister.requestCost(source, json, maxResponseBytes);
        let cycles = switch cyclesResult {
            case (#Ok cycles) { cycles };
            case (#Err err) {
                Debug.trap("unexpected error for `request_cost`: " # (debug_show err));
            };
        };

        let resultWithoutCycles = await EvmRpcCanister.request(source, json, maxResponseBytes);
        assert switch resultWithoutCycles {
            case (#Err(#ProviderError(#TooFewCycles { expected }))) expected == cycles;
            case _ false;
        };

        let result = await mainnet.request("eth_gasPrice", #Array([]), 1000);
        label validate {
            switch result {
                case (#ok(#Object fields)) {
                    for ((key, val) in fields.vals()) {
                        switch (key, val) {
                            case ("result", #String val) {
                                assert Text.startsWith(val, #text "0x");
                                break validate;
                            };
                            case _ {};
                        };
                    };
                };
                case _ {};
            };
            Debug.trap(debug_show result);
        };

        let a1 = "0xc9b28dca7ea6c5e176a58ba9df53c30ba52c6642";
        let a2 = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";

        let m1 = #Data(Blob.toArray("hello"));
        let s1 = "0x5c0e32248c10f7125b32cae1de9988f2dab686031083302f85b0a82f78e9206516b272fb7641f3e8ab63cf9f3a9b9220b2d6ff2699dc34f0d000d7693ca1ea5e1c";

        let m2 = #Data(Blob.toArray("other"));
        let s2 = "0x27ae1f90fd65c86b07aae1287dba8715db7e429ff9bf700205cb8ac904c6ba071c8fb7c6f8b5e15338521fee95a452c6a688f1c6fec5eeddbfa680a2abf300341b";

        // Invalid address
        assert not (
            await EvmRpcCanister.verifyMessageSignature({
                address = a2;
                message = m1;
                signature = s1;
            })
        );

        // Invalid message
        assert not (
            await EvmRpcCanister.verifyMessageSignature({
                address = a1;
                message = m2;
                signature = s1;
            })
        );

        // Invalid signature
        assert not (
            await EvmRpcCanister.verifyMessageSignature({
                address = a1;
                message = m1;
                signature = s2;
            })
        );

        // Valid signatures
        assert (
            await EvmRpcCanister.verifyMessageSignature({
                address = a1;
                message = m1;
                signature = s1;
            })
        );
        assert (
            await EvmRpcCanister.verifyMessageSignature({
                address = a1;
                message = m2;
                signature = s2;
            })
        );
    };
};
