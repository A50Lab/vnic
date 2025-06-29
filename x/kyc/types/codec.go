package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// RegisterLegacyAminoCodec registers concrete types on the LegacyAmino codec
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterConcrete(&MsgVerifyKyc{}, "kyc/VerifyKyc", nil)
	cdc.RegisterConcrete(&MsgIssueCredential{}, "kyc/IssueCredential", nil)
	cdc.RegisterConcrete(&MsgRegisterIdentity{}, "kyc/RegisterIdentity", nil)
	cdc.RegisterConcrete(&MsgUpdateParams{}, "kyc/UpdateParams", nil)
}

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgVerifyKyc{},
	)

	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgIssueCredential{},
	)

	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRegisterIdentity{},
	)

	registrar.RegisterImplementations((*sdk.Msg)(nil),
		&MsgUpdateParams{},
	)
	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}
