import EthCanister "canister:ic_eth";

import Principal "mo:base/Principal";
import Eth "mo:eth";

actor class () {
    public shared ({ caller }) func test() {
        let rpc = Eth.Rpc(#Canister EthCanister);

        rpc.request(#Service("cloudflare-eth.com", #EthMainnet));
    };
};
