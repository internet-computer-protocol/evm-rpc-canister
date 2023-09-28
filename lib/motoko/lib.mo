import Principal "mo:base/Principal";
import JSON "mo:json.mo";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";

module {
    public type Source = {
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

    type RpcCanisterActor = actor {
        request : (Source, Text, Nat64) -> async { #Ok : Blob; #Err : Error };
    };

    public class RpcCanister(id : Text) = this {
        let actor_ = actor (id) : RpcCanisterActor;
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
            switch (await actor_.request(source, payload, maxResponseBytes)) {
                case (#Ok x) { #ok x };
                case (#Err x) { #err x };
            };
        };
    };
};
