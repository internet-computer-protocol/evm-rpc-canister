import EthCanister "canister:ic_eth";

import Principal "mo:base/Principal";
import Eth "mo:eth";
import Debug "mo:base/Debug";

actor class Main() {
    let rpc = Eth.Rpc(
        #Canister EthCanister,
        #Service {
            hostname = "cloudflare-eth.com";
            network = ? #EthMainnet;
        },
    );

    public shared ({ caller }) func test() : async () {
        let source = #Service {
            hostname = "cloudflare-eth.com";
            chain_id = ?(1 : Nat64); // Ethereum mainnet
        };
        let json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}";
        let maxResponseBytes : Nat64 = 1000;

        let cyclesResult = await EthCanister.request_cost(source, json, maxResponseBytes);
        let cycles = switch cyclesResult {
            case (#Ok cycles) { cycles };
            case (#Err err) {
                Debug.trap("unexpected error for `request_cost`: " # (debug_show err));
            };
        };

        let resultWithoutCycles = await EthCanister.request(source, json, maxResponseBytes);
        assert switch resultWithoutCycles {
            case (#Err(#TooFewCycles { expected })) expected == cycles;
            case _ false;
        };

        // TODO: call with cycles

        // let result = await rpc.request("eth_gasPrice", #Null, 1000);
    };
};
