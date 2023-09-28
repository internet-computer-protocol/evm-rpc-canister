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
        #Custom : Nat64;
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
            #Ok : [Nat8];
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
            case (#Custom n) { n };
        };
    };

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

    public class Rpc(provider : Provider) = this {
        let actor_ = switch provider {
            case (#Canister a) { a };
            case (#Principal p) { actor (Principal.toText(p)) : RpcActor };
        };

        var nextId : Nat = 0;

        public func request(source : Source, method : Text, params : JSON.JSON, maxResponseBytes : Nat64) : async Result<JSON.JSON> {
            nextId += 1;
            // prettier-ignore
            let payload = JSON.show(#Object([
                ("id", #Number(nextId)),
                ("jsonrpc", #String("2.0")),
                ("method", #String(method)),
                ("params", params),
            ]));
            switch (await requestPlain(source, payload, maxResponseBytes)) {
                case (#ok blob) {
                    switch (Text.decodeUtf8(blob)) {
                        case (?text) {
                            switch (JSON.parse(text)) {
                                case (?json) { #ok json };
                                case null { #err(#ResponseParseError) };
                            };
                        };
                        case null { #err(#ResponseParseError) };
                    };
                };
                case (#err err) { #err err };
            };
        };

        public func requestPlain(source : Source, payload : Text, maxResponseBytes : Nat64) : async Result<Blob> {
            switch (await actor_.request(getActorSource(source), payload, maxResponseBytes)) {
                case (#Ok x) { #ok(Blob.fromArray(x)) };
                case (#Err x) { #err x };
            };
        };
    };
};
