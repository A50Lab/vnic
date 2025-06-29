package keeper

import (
	"context"
	"encoding/json"

	errorsmod "cosmossdk.io/errors"
	"vnic/x/kyc/types"
)


func (k msgServer) UpdateIdentity(ctx context.Context, msg *types.MsgUpdateIdentity) (*types.MsgUpdateIdentityResponse, error) {
	// Validate issuer address
	if _, err := k.addressCodec.StringToBytes(msg.Issuer); err != nil {
		return nil, errorsmod.Wrap(err, "invalid issuer address")
	}

	// Check if issuer is authorized
	issuer, err := k.Issuers.Get(ctx, msg.Issuer)
	if err != nil {
		return nil, errorsmod.Wrapf(types.ErrIssuerNotFound, "issuer not found: %s", msg.Issuer)
	}

	// Check if issuer is active
	if !issuer.Active {
		return nil, errorsmod.Wrapf(types.ErrIssuerNotActive, "issuer is not active: %s", msg.Issuer)
	}

	// Check if issuer can grant this KYC level
	if msg.KycLevel > issuer.MaxKycLevel {
		return nil, errorsmod.Wrapf(types.ErrInvalidKYCLevel, "issuer cannot grant KYC level %d (max: %d)", msg.KycLevel, issuer.MaxKycLevel)
	}

	// Check if identity exists
	identityJSON, err := k.Identities.Get(ctx, msg.IdentityId)
	if err != nil {
		return nil, errorsmod.Wrapf(types.ErrIdentityNotFound, "identity not found: %s", msg.IdentityId)
	}

	// Parse identity
	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return nil, errorsmod.Wrap(err, "failed to parse identity")
	}

	// Note: Owner consent verification is now handled through ZK proofs
	// When the issuer submits this update transaction, they must provide a ZK proof
	// that demonstrates they have authorization from the identity owner

	// Update KYC level
	identity.KYCLevel = msg.KycLevel

	// Update attributes
	if identity.Attributes == nil {
		identity.Attributes = make(map[string]string)
	}
	for k, v := range msg.Attributes {
		identity.Attributes[k] = v
	}
	// Add issuer info
	identity.Attributes["last_updated_by"] = msg.Issuer
	identity.Attributes["last_updated_at"] = "block_height" // TODO: get actual block height

	// Marshal and store updated identity
	updatedJSON, err := json.Marshal(identity)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to marshal identity")
	}

	if err := k.Identities.Set(ctx, msg.IdentityId, string(updatedJSON)); err != nil {
		return nil, errorsmod.Wrap(err, "failed to update identity")
	}

	// Update KYC level mapping if identity has a creator address
	if identity.Creator != "" {
		if err := k.KYCLevels.Set(ctx, identity.Creator, msg.KycLevel); err != nil {
			return nil, errorsmod.Wrap(err, "failed to update KYC level mapping")
		}
	}

	return &types.MsgUpdateIdentityResponse{}, nil
}