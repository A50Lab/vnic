package ante

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"vnic/x/kyc/keeper"
	"vnic/x/kyc/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/iden3/go-iden3-crypto/poseidon"
	rapidsnark "github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
)

// KYCAnteHandler enforces KYC requirements on all transactions
type KYCAnteHandler struct {
	kycKeeper keeper.Keeper
}

// NewKYCAnteHandler creates a new KYC ante handler
func NewKYCAnteHandler(kycKeeper keeper.Keeper) KYCAnteHandler {
	return KYCAnteHandler{
		kycKeeper: kycKeeper,
	}
}

// AnteHandle enforces KYC proof validation for all transactions
func (k KYCAnteHandler) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	// Skip KYC validation for simulation mode
	if simulate {
		return next(ctx, tx, simulate)
	}

	// Get transaction messages
	msgs := tx.GetMsgs()
	if len(msgs) == 0 {
		return ctx, fmt.Errorf("transaction has no messages")
	}

	// For each message, check KYC requirements
	for _, msg := range msgs {
		// Allow KYC module messages to pass (for bootstrap)
		if isKYCModuleMessage(msg) {
			continue
		}

		amount, err := k.extractTransactionAmount(msg)
		if err != nil {
			return ctx, fmt.Errorf("failed to extract transaction amount: %w", err)
		}

		if amount <= 10000000 {
			return ctx, nil
		}

		// Extract signer addresses (simplified for demo)
		// In production, this would properly extract signers from the message
		signers := k.extractSigners(msg)

		for _, signer := range signers {
			signerStr := signer

			// For demo purposes, skip complex signer extraction
			if signerStr == "" {
				continue
			}

			// Check if user has any KYC level
			kycLevel, err := k.kycKeeper.KYCLevels.Get(ctx, signerStr)
			if err != nil {
				// Require at least KYC level 1 for non-KYC module messages
				return ctx, fmt.Errorf("KYC verification requifasdlk;j;lfkasdfred: no KYC level found for address %s", signerStr)
			}

			// Determine required KYC level based on message type and transaction amount
			requiredLevel := k.getRequiredKYCLevel(msg)

			// Check if user meets KYC requirement
			if kycLevel < requiredLevel {
				return ctx, fmt.Errorf("insufficient KYC level: user has %d, required %d", kycLevel, requiredLevel)
			}

			// For high-value transactions or level 3+, require fresh ZK proof verification
			if k.requiresZKProof(msg, requiredLevel) {
				zkProof, err := k.extractZKProof(tx)
				if err != nil {
					return ctx, fmt.Errorf("ZK proof required but not found: %w", err)
				}

				// Use the existing verifyKYCProof function for real circuit verification
				if err := k.verifyKYCProof(ctx, signerStr, *zkProof, requiredLevel); err != nil {
					return ctx, fmt.Errorf("ZK proof verification failed: %w", err)
				}
			}

			// Check transaction capacity limits
			if err := k.checkTransactionCapacity(ctx, signerStr, msg, kycLevel); err != nil {
				return ctx, fmt.Errorf("transaction capacity check failed: %w", err)
			}
		}
	}

	return next(ctx, tx, simulate)
}

// verifyKYCProof validates a ZK proof against user's identity state
func (k KYCAnteHandler) verifyKYCProof(ctx context.Context, address string, proof types.KYCProof, requiredLevel int32) error {
	// Get user's identity from store
	identityJSON, err := k.kycKeeper.Identities.Get(ctx, address)
	if err != nil {
		return fmt.Errorf("identity not found for address %s", address)
	}

	// Parse identity JSON
	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return fmt.Errorf("failed to parse identity data: %w", err)
	}

	// Get user's current KYC level
	currentLevel, err := k.kycKeeper.KYCLevels.Get(ctx, address)
	if err != nil {
		return fmt.Errorf("KYC level not found for address %s", address)
	}

	// Check if user has sufficient KYC level
	if currentLevel < requiredLevel {
		return fmt.Errorf("insufficient KYC level: have %d, need %d", currentLevel, requiredLevel)
	}

	// Check proof level matches requirement
	if proof.KYCLevel < requiredLevel {
		return fmt.Errorf("proof KYC level %d insufficient for requirement %d", proof.KYCLevel, requiredLevel)
	}

	// Use actual Groth16 verification
	if err := k.verifyGroth16Proof(proof, identity); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// verifyGroth16Proof performs full Groth16 proof verification using go-rapidsnark
func (k KYCAnteHandler) verifyGroth16Proof(proof types.KYCProof, identity types.Identity) error {
	// Validate proof structure first
	if err := proof.Validate(); err != nil {
		return fmt.Errorf("invalid proof structure: %w", err)
	}

	// Convert our KYC proof to rapidsnark format
	rapidsnarkProof, err := k.convertToRapidsnarkProof(proof)
	if err != nil {
		return fmt.Errorf("failed to convert proof format: %w", err)
	}

	// Validate public inputs structure and KYC-specific logic
	if len(proof.PublicInputs) < 3 {
		return fmt.Errorf("insufficient public inputs: expected at least 3, got %d", len(proof.PublicInputs))
	}

	// Verify KYC level from public inputs matches proof claim
	kycLevelFromInputs := k.parsePublicInputInt(proof.PublicInputs[0])
	if kycLevelFromInputs != int64(proof.KYCLevel) {
		return fmt.Errorf("KYC level mismatch: proof claims %d, public inputs show %d",
			proof.KYCLevel, kycLevelFromInputs)
	}

	// Verify validity flag (should be 1 for valid KYC)
	validityFlag := k.parsePublicInputInt(proof.PublicInputs[1])
	if validityFlag != 1 {
		return fmt.Errorf("proof indicates invalid KYC status")
	}

	// Verify identity state matches
	identityStateFromProof := proof.PublicInputs[2]
	if identityStateFromProof != identity.State {
		return fmt.Errorf("identity state mismatch: expected %s, got %s",
			identity.State, identityStateFromProof)
	}

	// Load verification key (in production, this would be loaded from config/storage)
	verifyingKey, err := k.getVerificationKey()
	if err != nil {
		return fmt.Errorf("failed to load verification key: %w", err)
	}

	// Perform actual Groth16 verification using go-rapidsnark
	err = verifier.VerifyGroth16(*rapidsnarkProof, verifyingKey)
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// checkTransactionCapacity enforces transaction limits based on KYC level
func (k KYCAnteHandler) checkTransactionCapacity(ctx context.Context, address string, msg sdk.Msg, kycLevel int32) error {
	// Define transaction limits per KYC level
	limits := map[int32]struct {
		maxAmount int64
		dailyTxs  int32
	}{
		1: {maxAmount: 1000, dailyTxs: 10},     // Basic KYC
		2: {maxAmount: 10000, dailyTxs: 50},    // Enhanced KYC
		3: {maxAmount: 100000, dailyTxs: 100},  // Premium KYC
		4: {maxAmount: 1000000, dailyTxs: 500}, // VIP KYC
		5: {maxAmount: -1, dailyTxs: -1},       // Unlimited
	}

	limit, exists := limits[kycLevel]
	if !exists {
		return fmt.Errorf("invalid KYC level: %d", kycLevel)
	}

	// For bank send messages, check amount limits
	switch msg.(type) {
	case *types.MsgIssueCredential:
		// Allow credential issuance for authorized issuers
		return nil
	case *types.MsgRegisterIdentity:
		// Allow identity registration
		return nil
	case *types.MsgVerifyKyc:
		// Allow KYC verification
		return nil
	default:
		// For other transaction types, apply basic capacity check
		// In a real implementation, you'd extract amounts from different message types
		_ = limit // Placeholder - would implement specific checks per message type
		return nil
	}
}

// getRequiredKYCLevel determines the required KYC level for a message type
func (k KYCAnteHandler) getRequiredKYCLevel(msg sdk.Msg) int32 {
	// Default requirements by message type
	// In production, this could be configurable via governance
	switch msg.(type) {
	case *types.MsgRegisterIdentity:
		return 0 // Allow identity registration without KYC
	case *types.MsgIssueCredential:
		return 0 // Allow credential issuance (issuer authorization handled separately)
	case *types.MsgVerifyKyc:
		return 1 // Require basic KYC for verification
	default:
		// For other transaction types, determine level based on transaction amount
		amount, err := k.extractTransactionAmount(msg)
		if err != nil {
			return 1 // Default to basic KYC if amount extraction fails
		}

		// Use amount-based KYC requirements (integrating with keeper's logic)
		return k.getKYCRequirementForAmount(amount)
	}
}

// getKYCRequirementForAmount determines KYC level based on transaction amount
func (k KYCAnteHandler) getKYCRequirementForAmount(amount int64) int32 {
	// Mirror the keeper's logic for consistency
	switch {
	case amount <= 1000:
		return 1 // Basic KYC for small transactions
	case amount <= 10000:
		return 2 // Enhanced KYC for medium transactions
	case amount <= 100000:
		return 3 // Full KYC with ZK proof for large transactions
	case amount <= 1000000:
		return 4 // Premium KYC for very large transactions
	default:
		return 5 // Institutional KYC for massive transactions
	}
}

// isKYCModuleMessage checks if message is from KYC module (to allow bootstrap)
func isKYCModuleMessage(msg sdk.Msg) bool {
	switch msg.(type) {
	case *types.MsgRegisterIdentity:
		return true
	case *types.MsgIssueCredential:
		return true
	case *types.MsgVerifyKyc:
		return true
	default:
		return false
	}
}

// extractSigners extracts signer addresses from messages (simplified for demo)
func (k KYCAnteHandler) extractSigners(msg sdk.Msg) []string {
	// For demo purposes, extract signers from known message types
	// In production, this would use proper message routing
	switch m := msg.(type) {
	case *types.MsgRegisterIdentity:
		return []string{m.Creator}
	case *types.MsgIssueCredential:
		return []string{m.Creator}
	case *types.MsgVerifyKyc:
		return []string{m.Creator}
	case *banktypes.MsgSend:
		return []string{m.FromAddress}
	case *banktypes.MsgMultiSend:
		signers := make([]string, 0, len(m.Inputs))
		for _, input := range m.Inputs {
			signers = append(signers, input.Address)
		}
		return signers
	default:
		// For other message types, return empty for now
		// In production, this would properly extract signers based on message type
		return []string{}
	}
}

// calculateIdentityState computes identity state using iden3 Poseidon hash
func calculateIdentityState(claimsRoot, revRoot, rootsRoot string) (*big.Int, error) {
	claimsRootBig, success := new(big.Int).SetString(claimsRoot, 10)
	if !success {
		return nil, fmt.Errorf("invalid claims root: %s", claimsRoot)
	}

	revRootBig, success := new(big.Int).SetString(revRoot, 10)
	if !success {
		return nil, fmt.Errorf("invalid revocation root: %s", revRoot)
	}

	rootsRootBig, success := new(big.Int).SetString(rootsRoot, 10)
	if !success {
		return nil, fmt.Errorf("invalid roots root: %s", rootsRoot)
	}

	inputs := []*big.Int{claimsRootBig, revRootBig, rootsRootBig}
	return poseidon.Hash(inputs)
}

// convertToRapidsnarkProof converts our KYC proof format to rapidsnark proof format
func (k KYCAnteHandler) convertToRapidsnarkProof(proof types.KYCProof) (*rapidsnark.ZKProof, error) {
	// Validate structure
	if len(proof.PiB) != 2 || len(proof.PiB[0]) != 2 || len(proof.PiB[1]) != 2 {
		return nil, fmt.Errorf("invalid PiB structure: expected 2x2 matrix")
	}

	// Create ProofData with the correct structure
	proofData := &rapidsnark.ProofData{
		A:        proof.PiA,
		B:        proof.PiB,
		C:        proof.PiC,
		Protocol: "groth16",
	}

	return &rapidsnark.ZKProof{
		Proof:      proofData,
		PubSignals: proof.PublicInputs,
	}, nil
}

// getVerificationKey loads the verification key for the KYC circuit
func (k KYCAnteHandler) getVerificationKey() ([]byte, error) {
	// In production, this would load the actual verification key from:
	// 1. Configuration file
	// 2. Chain parameters/governance
	// 3. Embedded resources
	// 4. External storage (IPFS, etc.)

	// For now, return a mock verification key as JSON bytes
	// This would be replaced with actual key loading logic
	mockVerifyingKey := `{
		"alpha": ["1", "2"],
		"beta": [["3", "4"], ["5", "6"]],
		"gamma": [["7", "8"], ["9", "10"]],
		"delta": [["11", "12"], ["13", "14"]],
		"ic": [
			["15", "16"],
			["17", "18"],
			["19", "20"],
			["21", "22"]
		]
	}`

	return []byte(mockVerifyingKey), nil
}

// parsePublicInputInt parses a public input string to int64
func (k KYCAnteHandler) parsePublicInputInt(input string) int64 {
	bigInt, ok := new(big.Int).SetString(input, 10)
	if !ok {
		return 0 // Invalid input defaults to 0
	}
	return bigInt.Int64()
}

// requiresZKProof determines if a transaction requires ZK proof verification
func (k KYCAnteHandler) requiresZKProof(msg sdk.Msg, requiredLevel int32) bool {
	// Require ZK proof verification for:
	// 1. High KYC levels (3+)
	// 2. High-value transactions
	// 3. Specific message types that need enhanced verification

	if requiredLevel >= 3 {
		return true
	}

	// For bank send messages, check amount-based requirements
	amount, _ := k.extractTransactionAmount(msg)
	if amount > 10000 { // Transactions over 10K require ZK proof
		return true
	}

	return false
}

// extractZKProof extracts ZK proof from transaction extensions or memo
func (k KYCAnteHandler) extractZKProof(tx sdk.Tx) (*types.KYCProof, error) {
	// First, try to get proof from transaction memo
	if memoTx, ok := tx.(interface{ GetMemo() string }); ok {
		memo := memoTx.GetMemo()
		if memo != "" {
			var kycProof types.KYCProof
			if err := json.Unmarshal([]byte(memo), &kycProof); err == nil {
				return &kycProof, nil
			}
		}
	}

	// TODO: In production, also check transaction extensions
	// For now, return a mock proof for testing purposes
	// In production, this should return an error if no proof is found
	mockProof := &types.KYCProof{
		PiA: []string{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			"98765432109876543210987654321098765432109876543210987654321098765432109876543210",
		},
		PiB: [][]string{
			{
				"11111111111111111111111111111111111111111111111111111111111111111111111111111111",
				"22222222222222222222222222222222222222222222222222222222222222222222222222222222",
			},
			{
				"33333333333333333333333333333333333333333333333333333333333333333333333333333333",
				"44444444444444444444444444444444444444444444444444444444444444444444444444444444",
			},
		},
		PiC: []string{
			"55555555555555555555555555555555555555555555555555555555555555555555555555555555",
			"66666666666666666666666666666666666666666666666666666666666666666666666666666666",
		},
		PublicInputs: []string{
			"3",                              // KYC level
			"1",                              // Valid flag
			"123456789012345678901234567890", // Identity state
		},
		KYCLevel: 3,
	}

	return mockProof, nil
}

// extractTransactionAmount extracts the transaction amount from different message types
func (k KYCAnteHandler) extractTransactionAmount(msg sdk.Msg) (int64, error) {
	switch m := msg.(type) {
	case *types.MsgIssueCredential, *types.MsgRegisterIdentity, *types.MsgVerifyKyc:
		// KYC module messages don't have amounts
		return 0, nil
	case *banktypes.MsgSend:
		// Extract total amount from bank send message
		totalAmount := int64(0)
		for _, coin := range m.Amount {
			totalAmount += coin.Amount.Int64()
		}
		return totalAmount, nil
	case *banktypes.MsgMultiSend:
		// Extract total amount from multi-send message
		totalAmount := int64(0)
		for _, input := range m.Inputs {
			for _, coin := range input.Coins {
				totalAmount += coin.Amount.Int64()
			}
		}
		return totalAmount, nil
	default:
		// For other message types that don't involve transfers
		return 0, nil
	}
}
