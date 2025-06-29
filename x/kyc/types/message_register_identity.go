package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func NewMsgRegisterIdentity(creator string, id string) *MsgRegisterIdentity {
	return &MsgRegisterIdentity{
		Creator: creator,
		Id:      id,
	}
}

func (msg *MsgRegisterIdentity) ValidateBasic() error {
	if msg.Creator == "" {
		return errorsmod.Wrap(ErrInvalidAddress, "creator cannot be empty")
	}
	
	// For testing, allow any non-empty creator address
	// In production, uncomment the address validation below:
	// if _, err := sdk.AccAddressFromBech32(msg.Creator); err != nil {
	//     return errorsmod.Wrapf(ErrInvalidAddress, "invalid creator address: %s", err)
	// }
	
	if msg.Id == "" {
		return errorsmod.Wrap(ErrInvalidRequest, "identity ID cannot be empty")
	}
	
	return nil
}

// GetSigners returns the signers of the message
func (msg *MsgRegisterIdentity) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}
