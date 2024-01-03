import EvmRpcCanister "canister:evm_rpc";

import Principal "mo:base/Principal";
import Evm "mo:evm";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Cycles "mo:base/ExperimentalCycles"

shared ({ caller = installer }) actor class Main() {
    let mainnet = Evm.Rpc(
        #Canister EvmRpcCanister,
        #Service {
            hostname = "cloudflare-eth.com";
            network = ? #EthMainnet;
        },
    );

    public shared ({ caller }) func test() : async () {
        assert caller == installer;

        let source = #Service {
            hostname = "cloudflare-eth.com";
            chainId = ?(1 : Nat64); // Ethereum mainnet
        };
        let json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}";
        let maxResponseBytes : Nat64 = 1000;

        // `requestCost()`
        let cyclesResult = await EvmRpcCanister.requestCost(source, json, maxResponseBytes);
        let cycles = switch cyclesResult {
            case (#Ok cycles) { cycles };
            case (#Err err) {
                Debug.trap("unexpected error for `request_cost`: " # (debug_show err));
            };
        };

        // `request()` without cycles
        let resultWithoutCycles = await EvmRpcCanister.request(source, json, maxResponseBytes);
        assert switch resultWithoutCycles {
            case (#Err(#ProviderError(#TooFewCycles { expected }))) expected == cycles;
            case _ false;
        };

        // `request()` with cycles
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

        // Candid-RPC methods
        type RpcResult<T> = { #Ok : T; #Err : EvmRpcCanister.RpcError };
        type MultiRpcResult<T> = {
            #Consistent : RpcResult<T>;
            #Inconsistent : [(EvmRpcCanister.RpcService, RpcResult<T>)];
        };

        func assertOk<T>(method : Text, result : MultiRpcResult<T>) {
            switch result {
                case (#Consistent(#Ok _)) {};
                case (#Consistent(#Err err)) {
                    Debug.trap("received error for " # method # ": " # debug_show err);
                };
                case (#Inconsistent(results)) {
                    for ((service, result) in results.vals()) {
                        switch result {
                            case (#Ok(_)) {};
                            case (#Err(err)) {
                                Debug.trap("received error in inconsistent results for " # method # ": " # debug_show err);
                            };
                        };
                    };
                };
            };
        };

        let candidRpcCycles = 1_000_000_000_000;
        let ethMainnetSource = #EthMainnet(?[#Ankr, #BlockPi, #Cloudflare, #PublicNode]);

        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_getLogs",
            await EvmRpcCanister.eth_getLogs(
                ethMainnetSource,
                {
                    addresses = ["0xdAC17F958D2ee523a2206206994597C13D831ec7"];
                    fromBlock = null;
                    toBlock = null;
                    topics = null;
                },
            ),
        );
        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_getBlockByNumber",
            await EvmRpcCanister.eth_getBlockByNumber(ethMainnetSource, #Latest),
        );
        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_getTransactionReceipt",
            await EvmRpcCanister.eth_getTransactionReceipt(ethMainnetSource, "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"),
        );
        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_getTransactionCount",
            await EvmRpcCanister.eth_getTransactionCount(
                ethMainnetSource,
                {
                    address = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
                    block = #Latest;
                },
            ),
        );
        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_feeHistory",
            await EvmRpcCanister.eth_feeHistory(
                ethMainnetSource,
                {
                    blockCount = 3;
                    newestBlock = #Latest;
                    rewardPercentiles = null;
                },
            ),
        );
        Cycles.add(candidRpcCycles);
        assertOk(
            "eth_sendRawTransaction",
            await EvmRpcCanister.eth_sendRawTransaction(
                ethMainnetSource,
                "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
            ),
        );
    };
};
