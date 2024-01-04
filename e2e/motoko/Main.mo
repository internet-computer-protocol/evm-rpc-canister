import EvmRpcCanister "canister:evm_rpc";
import EvmRpcFidicuaryCanister "canister:evm_rpc_fiduciary";

import Blob "mo:base/Blob";
import Debug "mo:base/Debug";
import Cycles "mo:base/ExperimentalCycles";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Evm "mo:evm";

shared ({ caller = installer }) actor class Main() {
    public shared ({ caller }) func test() : async () {
        assert caller == installer;

        let canisterDetails = [
            // (`canister module`, `debug name`, `nodes in subnet`, `expected cycles for JSON-RPC call`)
            (EvmRpcCanister, "default", 13, 521_498_000),
            (EvmRpcFidicuaryCanister, "fiduciary", 28, 1_123_226_461),
        ];
        for ((canister, name, nodesInSubnet, expectedCycles) in canisterDetails.vals()) {
            Debug.print("Testing " # name # " canister...");

            let mainnet = Evm.Rpc(
                #Canister canister,
                #Service {
                    hostname = "cloudflare-eth.com";
                    network = ? #EthMainnet;
                },
            );

            let source = #Service {
                hostname = "cloudflare-eth.com";
                chainId = ?(1 : Nat64); // Ethereum mainnet
            };
            let json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}";
            let maxResponseBytes : Nat64 = 1000;

            // `requestCost()`
            let cyclesResult = await canister.requestCost(source, json, maxResponseBytes);
            let cycles = switch cyclesResult {
                case (#Ok cycles) { cycles };
                case (#Err err) {
                    Debug.trap("unexpected error for `request_cost`: " # (debug_show err));
                };
            };
            if (cycles != expectedCycles) {
                Debug.trap("unexpected number of cycles for " # name # " canister: " # debug_show cycles # " (expected " # debug_show expectedCycles # ")");
            };

            // `request()` without cycles
            let resultWithoutCycles = await canister.request(source, json, maxResponseBytes);
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

            // `request()` without sufficient cycles
            let resultWithoutEnoughCycles = await canister.request(source, json, maxResponseBytes);
            Cycles.add(cycles - 1);
            assert switch resultWithoutEnoughCycles {
                case (#Err(#ProviderError(#TooFewCycles { expected }))) expected == cycles;
                case _ false;
            };

            // Candid-RPC methods
            type RpcResult<T> = { #Ok : T; #Err : canister.RpcError };
            type MultiRpcResult<T> = {
                #Consistent : RpcResult<T>;
                #Inconsistent : [(canister.RpcService, RpcResult<T>)];
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
            let ethMainnetSource = #EthMainnet(?[#Ankr, #Cloudflare, #BlockPi, #PublicNode]);

            switch (await canister.eth_getBlockByNumber(ethMainnetSource, #Latest)) {
                case (#Consistent(#Err(#ProviderError(#TooFewCycles _)))) {};
                case result {
                    Debug.trap("received unexpected result: " # debug_show result);
                };
            };

            Cycles.add(candidRpcCycles);
            assertOk(
                "eth_getLogs",
                await canister.eth_getLogs(
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
                await canister.eth_getBlockByNumber(ethMainnetSource, #Latest),
            );
            Cycles.add(candidRpcCycles);
            assertOk(
                "eth_getTransactionReceipt",
                await canister.eth_getTransactionReceipt(ethMainnetSource, "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"),
            );
            Cycles.add(candidRpcCycles);
            assertOk(
                "eth_getTransactionCount",
                await canister.eth_getTransactionCount(
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
                await canister.eth_feeHistory(
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
                await canister.eth_sendRawTransaction(
                    ethMainnetSource,
                    "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
                ),
            );
        };
    };
};
