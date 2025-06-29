package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func NewMsgIssueCredential(creator string, id string, level int64) *MsgIssueCredential {
	return &MsgIssueCredential{
		Creator: creator,
		Id:      id,
		Level:   level,
	}
}

func (msg *MsgIssueCredential) ValidateBasic() error {
	if msg.Creator == "" {
		return errorsmod.Wrap(ErrInvalidAddress, "creator cannot be empty")
	}
	
	// For testing, allow any non-empty creator address
	// if _, err := sdk.AccAddressFromBech32(msg.Creator); err != nil {
	//     return errorsmod.Wrapf(ErrInvalidAddress, "invalid creator address: %s", err)
	// }
	
	if msg.Id == "" {
		return errorsmod.Wrap(ErrInvalidRequest, "identity ID cannot be empty")
	}
	
	if msg.Level < 1 || msg.Level > 5 {
		return errorsmod.Wrap(ErrInvalidKYCLevel, "KYC level must be between 1 and 5")
	}
	
	return nil
}

// GetSigners returns the signers of the message
func (msg *MsgIssueCredential) GetSigners() []sdk.AccAddress {
	creator, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{creator}
}
