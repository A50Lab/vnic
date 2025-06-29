package keeper

import (
	"context"
	"encoding/json"

	"vnic/x/kyc/types"

	errorsmod "cosmossdk.io/errors"
)

func (k msgServer) VerifyKyc(ctx context.Context, msg *types.MsgVerifyKyc) (*types.MsgVerifyKycResponse, error) {
	if _, err := k.addressCodec.StringToBytes(msg.Creator); err != nil {
		return nil, errorsmod.Wrap(err, "invalid creator address")
	}

	// Parse the ZK proof from JSON string
	var proof types.KYCProof
	if err := json.Unmarshal([]byte(msg.Proof), &proof); err != nil {
		return nil, errorsmod.Wrap(err, "invalid proof format")
	}

	// Validate proof structure
	if err := proof.Validate(); err != nil {
		return nil, err
	}

	// Verify the required KYC level
	if msg.Level < 1 || msg.Level > 5 {
		return nil, types.ErrInvalidKYCLevel
	}

	// Get user's current KYC level
	currentLevel, err := k.KYCLevels.Get(ctx, msg.Creator)
	if err != nil {
		return nil, types.ErrIdentityNotFound
	}

	// Check if user has sufficient KYC level
	if currentLevel < int32(msg.Level) {
		return nil, types.ErrInsufficientKYC
	}

	// For hackathon demo: simplified proof verification
	// In production, this would use actual Groth16 verification with iden3 circuits
	verified := k.verifyKYCProofSimplified(proof, currentLevel)
	if !verified {
		return nil, types.ErrProofVerification
	}

	return &types.MsgVerifyKycResponse{}, nil
}

// verifyKYCProofSimplified performs basic validation for hackathon demo
func (k msgServer) verifyKYCProofSimplified(proof types.KYCProof, userLevel int32) bool {
	// Basic validation - proof KYC level should not exceed user's actual level
	if proof.KYCLevel > userLevel {
		return false
	}
	
	// Validate proof has reasonable structure
	if len(proof.PiA) != 2 || len(proof.PiC) != 2 {
		return false
	}
	
	if len(proof.PiB) != 2 {
		return false
	}
	
	for _, row := range proof.PiB {
		if len(row) != 2 {
			return false
		}
	}
	
	// For demo: always return true if structure is valid
	return true
}
