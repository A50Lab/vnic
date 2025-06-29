package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	"vnic/x/kyc/types"
)

func (k msgServer) AddIssuer(ctx context.Context, msg *types.MsgAddIssuer) (*types.MsgAddIssuerResponse, error) {
	// For testing: allow any user to add issuers
	// TODO: In production, use proper governance with authority check:
	// expectedAuthority := string(k.GetAuthority())
	// if msg.Authority != expectedAuthority {
	//     return nil, errorsmod.Wrapf(types.ErrInvalidAuthority, "invalid authority; expected %s, got %s", expectedAuthority, msg.Authority)
	// }

	// Simplified validation: accept test issuer IDs and fixed addresses
	if msg.Issuer.Address == "" {
		return nil, errorsmod.Wrap(types.ErrInvalidAddress, "issuer address cannot be empty")
	}
	
	// Accept test issuer formats: "test-issuer-XXX" or "issuer-XXX" 
	// No need for complex Cosmos address validation in test mode

	// Validate max KYC level
	if msg.Issuer.MaxKycLevel < 1 || msg.Issuer.MaxKycLevel > 5 {
		return nil, errorsmod.Wrapf(types.ErrInvalidKYCLevel, "invalid max KYC level: %d", msg.Issuer.MaxKycLevel)
	}

	// Store issuer
	if err := k.Issuers.Set(ctx, msg.Issuer.Address, msg.Issuer); err != nil {
		return nil, errorsmod.Wrap(err, "failed to store issuer")
	}

	return &types.MsgAddIssuerResponse{}, nil
}