package keeper

import (
	"context"
	"encoding/json"
	"math/big"

	"vnic/x/kyc/types"

	"github.com/iden3/go-iden3-crypto/poseidon"
	errorsmod "cosmossdk.io/errors"
)

// IdentityState represents the three trees that make up an identity state
type IdentityState struct {
	ClaimsTreeRoot      *big.Int `json:"claims_tree_root"`
	RevocationsTreeRoot *big.Int `json:"revocations_tree_root"`
	RootsTreeRoot       *big.Int `json:"roots_tree_root"`
}

// NewIdentityState creates a new identity state with empty trees
func NewIdentityState() *IdentityState {
	return &IdentityState{
		ClaimsTreeRoot:      big.NewInt(0),
		RevocationsTreeRoot: big.NewInt(0),
		RootsTreeRoot:       big.NewInt(0),
	}
}

// CalculateState computes the identity state using Poseidon hash
func (is *IdentityState) CalculateState() (*big.Int, error) {
	inputs := []*big.Int{
		is.ClaimsTreeRoot,
		is.RevocationsTreeRoot,
		is.RootsTreeRoot,
	}
	return poseidon.Hash(inputs)
}

// GetIdentityState retrieves an identity state by ID
func (k Keeper) GetIdentityState(ctx context.Context, identityID string) (*IdentityState, error) {
	identityJSON, err := k.Identities.Get(ctx, identityID)
	if err != nil {
		return nil, errorsmod.Wrap(types.ErrIdentityNotFound, identityID)
	}

	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return nil, errorsmod.Wrap(err, "failed to unmarshal identity")
	}

	// Parse stored tree roots
	claimsRoot, ok := new(big.Int).SetString(identity.ClaimsRoot, 10)
	if !ok {
		claimsRoot = big.NewInt(0)
	}

	revRoot, ok := new(big.Int).SetString(identity.RevRoot, 10)
	if !ok {
		revRoot = big.NewInt(0)
	}

	rootsRoot, ok := new(big.Int).SetString(identity.RootsRoot, 10)
	if !ok {
		rootsRoot = big.NewInt(0)
	}

	return &IdentityState{
		ClaimsTreeRoot:      claimsRoot,
		RevocationsTreeRoot: revRoot,
		RootsTreeRoot:       rootsRoot,
	}, nil
}

// UpdateIdentityState updates the identity state in storage
func (k Keeper) UpdateIdentityState(ctx context.Context, identityID string, state *IdentityState) error {
	// Get existing identity
	identityJSON, err := k.Identities.Get(ctx, identityID)
	if err != nil {
		return errorsmod.Wrap(types.ErrIdentityNotFound, identityID)
	}

	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return errorsmod.Wrap(err, "failed to unmarshal identity")
	}

	// Calculate new state hash
	stateHash, err := state.CalculateState()
	if err != nil {
		return errorsmod.Wrap(err, "failed to calculate state hash")
	}

	// Update identity with new state
	identity.State = stateHash.String()
	identity.ClaimsRoot = state.ClaimsTreeRoot.String()
	identity.RevRoot = state.RevocationsTreeRoot.String()
	identity.RootsRoot = state.RootsTreeRoot.String()

	// Serialize and store
	updatedJSON, err := json.Marshal(identity)
	if err != nil {
		return errorsmod.Wrap(err, "failed to marshal identity")
	}

	return k.Identities.Set(ctx, identityID, string(updatedJSON))
}

// AddClaim adds a claim to the identity's claims tree
func (k Keeper) AddClaim(ctx context.Context, identityID string, claimIndex, claimValue *big.Int) error {
	state, err := k.GetIdentityState(ctx, identityID)
	if err != nil {
		return err
	}

	// For simplified implementation, we'll use a simple hash combination
	// In production, this would involve actual sparse merkle tree operations
	newClaimsRoot := k.hashTreeAddition(state.ClaimsTreeRoot, claimIndex, claimValue)
	state.ClaimsTreeRoot = newClaimsRoot

	return k.UpdateIdentityState(ctx, identityID, state)
}

// RevokeClaim adds a revocation nonce to the revocations tree
func (k Keeper) RevokeClaim(ctx context.Context, identityID string, nonce *big.Int) error {
	state, err := k.GetIdentityState(ctx, identityID)
	if err != nil {
		return err
	}

	// Add revocation (nonce -> 1)
	newRevRoot := k.hashTreeAddition(state.RevocationsTreeRoot, nonce, big.NewInt(1))
	state.RevocationsTreeRoot = newRevRoot

	return k.UpdateIdentityState(ctx, identityID, state)
}

// AddRoot adds a root to the roots tree (for state transitions)
func (k Keeper) AddRoot(ctx context.Context, identityID string, root *big.Int) error {
	state, err := k.GetIdentityState(ctx, identityID)
	if err != nil {
		return err
	}

	// Add new root (root -> timestamp or block number)
	blockHeight := k.GetBlockHeight(ctx)
	newRootsRoot := k.hashTreeAddition(state.RootsTreeRoot, root, big.NewInt(blockHeight))
	state.RootsTreeRoot = newRootsRoot

	return k.UpdateIdentityState(ctx, identityID, state)
}

// hashTreeAddition is a simplified tree addition using Poseidon hash
// In production, this would be replaced with actual sparse merkle tree operations
func (k Keeper) hashTreeAddition(currentRoot, key, value *big.Int) *big.Int {
	inputs := []*big.Int{currentRoot, key, value}
	result, _ := poseidon.Hash(inputs)
	return result
}

// GetBlockHeight gets the current block height from context
func (k Keeper) GetBlockHeight(ctx context.Context) int64 {
	// Extract block height from SDK context
	// This is a simplified implementation
	return 1 // TODO: Get actual block height from context
}

// IssueKYCCredential issues a KYC credential by adding claims to the identity
func (k Keeper) IssueKYCCredential(ctx context.Context, identityID string, kycLevel int32, attributes map[string]string) error {
	// Create claim for KYC level
	kycLevelClaim := &types.Claim{
		Schema:    types.KYCLevelSchema,
		SlotIndex: 0,
		SlotValue: big.NewInt(int64(kycLevel)),
	}

	// Add KYC level claim
	claimIndex := k.CalculateClaimIndex(kycLevelClaim)
	claimValue := kycLevelClaim.SlotValue
	
	if err := k.AddClaim(ctx, identityID, claimIndex, claimValue); err != nil {
		return errorsmod.Wrap(err, "failed to add KYC level claim")
	}

	// Update identity KYC level
	identityJSON, err := k.Identities.Get(ctx, identityID)
	if err != nil {
		return errorsmod.Wrap(types.ErrIdentityNotFound, identityID)
	}

	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return errorsmod.Wrap(err, "failed to unmarshal identity")
	}

	identity.KYCLevel = kycLevel
	for key, value := range attributes {
		identity.Attributes[key] = value
	}

	updatedJSON, err := json.Marshal(identity)
	if err != nil {
		return errorsmod.Wrap(err, "failed to marshal identity")
	}

	if err := k.Identities.Set(ctx, identityID, string(updatedJSON)); err != nil {
		return errorsmod.Wrap(err, "failed to store updated identity")
	}

	// Update KYC level mapping
	return k.KYCLevels.Set(ctx, identity.Creator, kycLevel)
}

// CalculateClaimIndex calculates the index for a claim in the claims tree
func (k Keeper) CalculateClaimIndex(claim *types.Claim) *big.Int {
	inputs := []*big.Int{
		claim.Schema,
		big.NewInt(int64(claim.SlotIndex)),
	}
	result, _ := poseidon.Hash(inputs)
	return result
}

// VerifyIdentityState verifies that an identity state is valid
func (k Keeper) VerifyIdentityState(ctx context.Context, identityID string, expectedState *big.Int) (bool, error) {
	currentState, err := k.GetIdentityState(ctx, identityID)
	if err != nil {
		return false, err
	}

	calculatedState, err := currentState.CalculateState()
	if err != nil {
		return false, err
	}

	return calculatedState.Cmp(expectedState) == 0, nil
}