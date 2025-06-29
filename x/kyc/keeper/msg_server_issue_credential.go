package keeper

import (
	"context"

	"vnic/x/kyc/types"

	errorsmod "cosmossdk.io/errors"
)

func (k msgServer) IssueCredential(ctx context.Context, msg *types.MsgIssueCredential) (*types.MsgIssueCredentialResponse, error) {
	if _, err := k.addressCodec.StringToBytes(msg.Creator); err != nil {
		return nil, errorsmod.Wrap(err, "invalid creator address")
	}

	// Check if creator is an authorized issuer
	issuer, err := k.Issuers.Get(ctx, msg.Creator)
	if err != nil {
		return nil, errorsmod.Wrapf(types.ErrIssuerNotFound, "issuer not found: %s", msg.Creator)
	}

	// Check if issuer is active
	if !issuer.Active {
		return nil, errorsmod.Wrapf(types.ErrIssuerNotActive, "issuer is not active: %s", msg.Creator)
	}

	// Validate KYC level
	if msg.Level < 1 || msg.Level > 5 {
		return nil, types.ErrInvalidKYCLevel
	}

	// Check if issuer can grant this KYC level
	if msg.Level > int64(issuer.MaxKycLevel) {
		return nil, errorsmod.Wrapf(types.ErrInvalidKYCLevel, "issuer cannot grant KYC level %d (max: %d)", msg.Level, issuer.MaxKycLevel)
	}

	// Check if identity exists
	_, err = k.Identities.Get(ctx, msg.Id)
	if err != nil {
		return nil, types.ErrIdentityNotFound
	}

	// Issue KYC credential using iden3 state management
	// This adds claims to the identity's claims tree and updates the state
	attributes := map[string]string{
		"kyc_level": string(rune(msg.Level)),
		"issued_by": msg.Creator,
		"issued_at": "block_height", // TODO: get actual block height
	}

	if err := k.IssueKYCCredential(ctx, msg.Id, int32(msg.Level), attributes); err != nil {
		return nil, errorsmod.Wrap(err, "failed to issue KYC credential")
	}

	return &types.MsgIssueCredentialResponse{}, nil
}
