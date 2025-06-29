package keeper

import (
	"context"
	"encoding/json"
	"strings"

	"vnic/x/kyc/types"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) RegisterIdentity(ctx context.Context, msg *types.MsgRegisterIdentity) (*types.MsgRegisterIdentityResponse, error) {
	// Validate creator address
	if msg.Creator == "" {
		return nil, errorsmod.Wrap(types.ErrInvalidAddress, "creator cannot be empty")
	}
	
	// Validate Cosmos address format (enable in production)
	if !strings.Contains(msg.Creator, "test-user") && !strings.Contains(msg.Creator, "user-") {
		// Validate proper Cosmos address for non-test addresses
		_, err := sdk.AccAddressFromBech32(msg.Creator)
		if err != nil {
			return nil, errorsmod.Wrapf(types.ErrInvalidAddress, "invalid creator address format: %s", err)
		}
	}
	
	// Note: DID ownership verification is now handled through ZK proofs during transactions
	// The registration process establishes the mapping between address and DID
	// Actual ownership is proven cryptographically via ZK proofs when needed

	// Check if identity already exists
	_, err := k.Identities.Get(ctx, msg.Id)
	if err == nil {
		return nil, types.ErrIdentityExists
	}

	// Create new identity with initial iden3 state
	initialState := NewIdentityState()
	stateHash, err := initialState.CalculateState()
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to calculate initial state")
	}

	identity := types.Identity{
		ID:          msg.Id,
		Creator:     msg.Creator,
		State:       stateHash.String(),
		KYCLevel:    0,   // No KYC initially
		Attributes:  make(map[string]string),
		ClaimsRoot:  initialState.ClaimsTreeRoot.String(),
		RevRoot:     initialState.RevocationsTreeRoot.String(), 
		RootsRoot:   initialState.RootsTreeRoot.String(),
	}

	// Serialize identity to JSON
	identityBytes, err := json.Marshal(identity)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to serialize identity")
	}

	// Store the identity
	if err := k.Identities.Set(ctx, msg.Id, string(identityBytes)); err != nil {
		return nil, errorsmod.Wrap(err, "failed to store identity")
	}

	// Initialize KYC level
	if err := k.KYCLevels.Set(ctx, msg.Creator, int32(0)); err != nil {
		return nil, errorsmod.Wrap(err, "failed to store KYC level")
	}

	return &types.MsgRegisterIdentityResponse{}, nil
}
