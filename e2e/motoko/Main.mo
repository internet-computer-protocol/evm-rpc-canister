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

    public func example() : async Text {

        let a = await rpc.gasPrice();
        let b = await rpc.request("eth_gasPrice", #Null, 1000);

        debug_show (a, b);
    };

    public shared ({ caller }) func test() : async () {
        // TODO
    };
};
