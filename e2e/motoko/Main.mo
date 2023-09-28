import EthCanister "canister:ic_eth";

import Principal "mo:base/Principal";
import Eth "mo:eth";
import Debug "mo:base/Debug";

actor class () {
    public shared ({ caller }) func test() : async Text {
        let rpc = Eth.Rpc(#Canister EthCanister);

        // assert  == #ok();
        debug_show (
            await rpc.request(
                #Service {
                    hostname = "cloudflare-eth.com";
                    network = ? #EthMainnet;
                },
                "eth_gasPrice",
                #Array([]),
                1000,
            )
        );
    };
};
