package kyc

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	"vnic/x/kyc/types"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: types.Query_serviceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod:      "Identity",
					Use:            "identity [id]",
					Short:          "Query identity",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}},
				},

				{
					RpcMethod:      "KycLevel",
					Use:            "kyc-level [address]",
					Short:          "Query kyc-level",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "address"}},
				},

				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              types.Msg_serviceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "RegisterIdentity",
					Use:            "register-identity [id]",
					Short:          "Send a register-identity tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}},
				},
				{
					RpcMethod:      "IssueCredential",
					Use:            "issue-credential [id] [level]",
					Short:          "Send a issue-credential tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}, {ProtoField: "level"}},
				},
				{
					RpcMethod:      "VerifyKyc",
					Use:            "verify-kyc [proof] [level]",
					Short:          "Send a verify-kyc tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "proof"}, {ProtoField: "level"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
