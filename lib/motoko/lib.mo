import Principal "mo:base/Principal";

module {
    type CanisterActor = actor { method : () -> async () };

    public class Canister(id : Text) {
        let a = actor (id) : CanisterActor;

        public func request() {
            // TODO
        }
    };
};
