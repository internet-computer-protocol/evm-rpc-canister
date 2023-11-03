// This is a generated Motoko binding.
// Please use `import service "ic:canister_id"` instead to call canisters on the IC if possible.

module {
  public type Auth = { #Rpc; #RegisterProvider; #FreeRpc; #Admin };
  public type Block = { base_fee_per_gas : Nat; number : Nat };
  public type BlockSpec = { #Tag : BlockTag; #Number : Nat };
  public type BlockTag = {
    #Earliest;
    #Safe;
    #Finalized;
    #Latest;
    #Number : Nat64;
    #Pending;
  };
  public type CandidRpcSource = {
    #Ethereum : ?EthereumProvider;
    #Sepolia : ?SepoliaProvider;
  };
  public type DataFormatError = { #InvalidHex : Text };
  public type EthereumProvider = { #Cloudflare; #Ankr };
  public type FeeHistory = {
    reward : [[Nat]];
    base_fee_per_gas : [Nat];
    oldest_block : Nat;
  };
  public type FeeHistoryArgs = {
    block_count : Nat;
    newest_block : BlockSpec;
    reward_percentiles : ?Blob;
  };
  public type GetLogsArgs = {
    addresses : [Text];
    topics : ?[Text];
    to_block : ?BlockSpec;
    from_block : ?BlockSpec;
  };
  public type GetTransactionCountArgs = { address : Text; block : BlockSpec };
  public type HttpOutcallError = {
    #IcError : { code : RejectionCode; message : Text };
    #InvalidHttpJsonRpcResponse : {
      status : Nat16;
      body : Text;
      parsing_error : ?Text;
    };
  };
  public type JsonRpcError = { code : Int64; message : Text };
  public type LogEntry = {
    transaction_hash : ?Blob;
    block_hash : ?Blob;
    log_index : ?Nat;
    data : Blob;
    transaction_index : ?Nat;
    block_number : ?Nat;
    topics : [Blob];
    address : Blob;
    removed : Bool;
  };
  public type Message = { #Data : Blob; #Hash : Blob };
  public type ProviderError = {
    #TooFewCycles : { expected : Nat; received : Nat };
    #ServiceUrlParseError : Text;
    #ProviderNotFound;
    #ServiceHostNotAllowed : Text;
    #NoPermission;
  };
  public type ProviderView = {
    owner : Principal;
    hostname : Text;
    provider_id : Nat64;
    cycles_per_message_byte : Nat64;
    primary : Bool;
    chain_id : Nat64;
    cycles_per_call : Nat64;
  };
  public type RegisterProvider = {
    hostname : Text;
    cycles_per_message_byte : Nat64;
    chain_id : Nat64;
    cycles_per_call : Nat64;
    credential_path : Text;
  };
  public type RejectionCode = {
    #NoError;
    #CanisterError;
    #SysTransient;
    #DestinationInvalid;
    #Unknown;
    #SysFatal;
    #CanisterReject;
  };
  public type Result = { #Ok : ?FeeHistory; #Err : RpcError };
  public type Result_1 = { #Ok : Block; #Err : RpcError };
  public type Result_2 = { #Ok : [LogEntry]; #Err : RpcError };
  public type Result_3 = { #Ok : Nat; #Err : RpcError };
  public type Result_4 = { #Ok : ?TransactionReceipt; #Err : RpcError };
  public type Result_5 = { #Ok : SendRawTransactionResult; #Err : RpcError };
  public type Result_6 = { #Ok : Text; #Err : RpcError };
  public type Result_7 = { #Ok : Nat; #Err : RpcError };
  public type RpcError = {
    #JsonRpcError : JsonRpcError;
    #ProviderError : ProviderError;
    #HttpOutcallError : HttpOutcallError;
    #DataFormatError : DataFormatError;
  };
  public type SendRawTransactionResult = {
    #Ok;
    #NonceTooLow;
    #NonceTooHigh;
    #InsufficientFunds;
  };
  public type SepoliaProvider = { #BlockPi; #PublicNode; #Ankr };
  public type SignedMessage = {
    signature : Blob;
    message : Message;
    address : Blob;
  };
  public type Source = {
    #Url : Text;
    #Service : { hostname : Text; chain_id : ?Nat64 };
    #Chain : Nat64;
    #Provider : Nat64;
  };
  public type TransactionReceipt = {
    effective_gas_price : Nat;
    status : TransactionStatus;
    transaction_hash : Blob;
    block_hash : Blob;
    block_number : Nat;
    gas_used : Nat;
  };
  public type TransactionStatus = { #Success; #Failure };
  public type UpdateProvider = {
    hostname : ?Text;
    provider_id : Nat64;
    cycles_per_message_byte : ?Nat64;
    primary : ?Bool;
    cycles_per_call : ?Nat64;
    credential_path : ?Text;
  };
  public type Self = actor {
    authorize : shared (Principal, Auth) -> async ();
    deauthorize : shared (Principal, Auth) -> async ();
    eth_fee_history : shared (CandidRpcSource, FeeHistoryArgs) -> async Result;
    eth_get_block_by_number : shared (
        CandidRpcSource,
        BlockSpec,
      ) -> async Result_1;
    eth_get_logs : shared (CandidRpcSource, GetLogsArgs) -> async Result_2;
    eth_get_transaction_count : shared (
        CandidRpcSource,
        GetTransactionCountArgs,
      ) -> async Result_3;
    eth_get_transaction_receipt : shared (
        CandidRpcSource,
        Blob,
      ) -> async Result_4;
    eth_send_raw_transaction : shared (CandidRpcSource, Text) -> async Result_5;
    get_accumulated_cycle_count : shared query Nat64 -> async Nat;
    get_authorized : shared query Auth -> async [Text];
    get_nodes_in_subnet : shared query () -> async Nat32;
    get_open_rpc_access : shared query () -> async Bool;
    get_providers : shared query () -> async [ProviderView];
    register_provider : shared RegisterProvider -> async Nat64;
    request : shared (Source, Text, Nat64) -> async Result_6;
    request_cost : shared query (Source, Text, Nat64) -> async Result_7;
    set_nodes_in_subnet : shared Nat32 -> async ();
    set_open_rpc_access : shared Bool -> async ();
    unregister_provider : shared Nat64 -> async Bool;
    update_provider : shared UpdateProvider -> async ();
    verify_signature : shared query SignedMessage -> async Bool;
    withdraw_accumulated_cycles : shared (Nat64, Principal) -> async ();
  }
}
