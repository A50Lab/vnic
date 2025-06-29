package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	"vnic/x/kyc/types"
)

func (k msgServer) RemoveIssuer(ctx context.Context, msg *types.MsgRemoveIssuer) (*types.MsgRemoveIssuerResponse, error) {
	// Check if the message is from the authority
	if msg.Authority != string(k.GetAuthority()) {
		return nil, errorsmod.Wrapf(types.ErrInvalidAuthority, "invalid authority; expected %s, got %s", k.GetAuthority(), msg.Authority)
	}

	// Validate issuer address
	if _, err := k.addressCodec.StringToBytes(msg.Address); err != nil {
		return nil, errorsmod.Wrap(err, "invalid issuer address")
	}

	// Check if issuer exists
	has, err := k.Issuers.Has(ctx, msg.Address)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to check issuer existence")
	}
	if !has {
		return nil, errorsmod.Wrapf(types.ErrIssuerNotFound, "issuer not found: %s", msg.Address)
	}

	// Remove issuer
	if err := k.Issuers.Remove(ctx, msg.Address); err != nil {
		return nil, errorsmod.Wrap(err, "failed to remove issuer")
	}

	return &types.MsgRemoveIssuerResponse{}, nil
}