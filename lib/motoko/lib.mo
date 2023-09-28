import Principal "mo:base/Principal";
import JSON "mo:json.mo";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Blob "mo:base/Blob";

module {
    public type Network = {
        #EthMainnet;
        #EthSepolia;
        #EthGoerli;
        #Network : Nat64;
    };

    public type Source = {
        #Url : Text;
        #Service : { hostname : Text; network : ?Network };
        #Chain : Network;
        #Provider : Nat64;
    };

    type ActorSource = {
        #Url : Text;
        #Service : { hostname : Text; chain_id : ?Nat64 };
        #Chain : Nat64;
        #Provider : Nat64;
    };

    public type Error = {
        // RPC canister errors
        #ServiceUrlHostNotAllowed;
        #HttpRequestError : { code : Nat32; message : Text };
        #TooFewCycles : { expected : Nat; received : Nat };
        #ServiceUrlParseError;
        #ServiceUrlHostMissing;
        #ProviderNotFound;
        #NoPermission;

        // Library errors
        #ResponseParseError;
    };

    public type Result<T> = {
        #ok : T;
        #err : Error;
    };

    public type RpcActor = actor {
        request : shared (ActorSource, Text, Nat64) -> async {
            #Ok : Text;
            #Err : Error;
        };
    };

    public type Provider = {
        #Canister : RpcActor;
        #Principal : Principal;
    };

    func getChainId(network : Network) : Nat64 {
        // Reference: https://chainlist.org/?testnets=true
        switch network {
            case (#EthMainnet) { 1 };
            case (#EthGoerli) { 5 };
            case (#EthSepolia) { 11155111 };
            case (#Network n) { n };
        };
    };

    public class Rpc(provider : Provider, source : Source) = this {

        func getActorSource(source : Source) : ActorSource {
            switch source {
                case (#Url s) { #Url s };
                case (#Service { hostname; network }) {
                    #Service {
                        hostname;
                        chain_id = switch network {
                            case (?n) { ?getChainId(n) };
                            case null { null };
                        };
                    };
                };
                case (#Chain n) { #Chain(getChainId(n)) };
                case (#Provider n) { #Provider n };
            };
        };

        let actor_ = switch provider {
            case (#Canister a) { a };
            case (#Principal p) { actor (Principal.toText(p)) : RpcActor };
        };
        let actorSource = getActorSource(source);

        var nextId : Nat = 0;
        public func request(method : Text, params : JSON.JSON, maxResponseBytes : Nat64) : async Result<JSON.JSON> {
            nextId += 1;
            // prettier-ignore
            let payload = JSON.show(#Object([
                ("id", #Number(nextId)),
                ("jsonrpc", #String("2.0")),
                ("method", #String(method)),
                ("params", params),
            ]));
            switch (await requestPlain(payload, maxResponseBytes)) {
                case (#ok text) {
                    switch (JSON.parse(text)) {
                        case (?json) { #ok json };
                        case null { #err(#ResponseParseError) };
                    };
                };
                case (#err err) { #err err };
            };
        };

        public func requestPlain(payload : Text, maxResponseBytes : Nat64) : async Result<Text> {
            switch (await actor_.request(actorSource, payload, maxResponseBytes)) {
                case (#Ok x) { #ok x };
                case (#Err x) { #err x };
            };
        };

        public func gasPrice() : async Nat {
            let result = request("eth_gasPrice", #Null, 256);
            // TODO: decode
            assert false;
            0;
        };
    };
};
