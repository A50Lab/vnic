package types

import (
	"math/big"
)

// KYC Claim Schemas
var (
	KYCLevelSchema = big.NewInt(1001) // Schema ID for KYC level claims
	AgeSchema      = big.NewInt(1002) // Schema ID for age claims
	CountrySchema  = big.NewInt(1003) // Schema ID for country claims
)

// Claim represents a claim in the identity system
type Claim struct {
	Schema    *big.Int `json:"schema"`
	SlotIndex int      `json:"slot_index"`
	SlotValue *big.Int `json:"slot_value"`
}

// Identity represents a user's KYC identity state
type Identity struct {
	ID          string            `json:"id"`
	Creator     string            `json:"creator"`
	State       string            `json:"state"`
	KYCLevel    int32             `json:"kyc_level"`
	Attributes  map[string]string `json:"attributes"`
	ClaimsRoot  string            `json:"claims_root"`
	RevRoot     string            `json:"rev_root"`
	RootsRoot   string            `json:"roots_root"`
}

// KYCProof represents a zero-knowledge proof for KYC verification
// This proof cryptographically demonstrates:
// 1. Identity ownership - prover knows the private key for the DID
// 2. KYC credential validity - prover has legitimate KYC credentials
// 3. Transaction authorization - prover is authorized to make this transaction
type KYCProof struct {
	PiA          []string   `json:"pi_a"`
	PiB          [][]string `json:"pi_b"`
	PiC          []string   `json:"pi_c"`
	PublicInputs []string   `json:"public_inputs"`
	KYCLevel     int32      `json:"kyc_level"`
	// DID is the identity identifier this proof pertains to
	DID          string     `json:"did"`
}

// KYCProofExtension represents a transaction extension containing KYC proof
type KYCProofExtension struct {
	Proof        *KYCProof `json:"proof"`
	PublicInputs []string  `json:"public_inputs"`
	KYCLevel     int32     `json:"kyc_level"`
}

// TransactionLimits defines transaction limits for different KYC levels
type TransactionLimits struct {
	MaxAmount     int64 `json:"max_amount"`
	DailyTxs      int32 `json:"daily_txs"`
	MonthlyVolume int64 `json:"monthly_volume"`
}

// Validate performs basic validation on KYCProof
func (p *KYCProof) Validate() error {
	if len(p.PiA) != 2 {
		return ErrInvalidProof
	}
	if len(p.PiB) != 2 || len(p.PiB[0]) != 2 || len(p.PiB[1]) != 2 {
		return ErrInvalidProof
	}
	if len(p.PiC) != 2 {
		return ErrInvalidProof
	}
	if p.KYCLevel < 0 || p.KYCLevel > 5 {
		return ErrInvalidKYCLevel
	}
	return nil
}

// ValidateExtension validates the KYC proof extension
func (ext *KYCProofExtension) ValidateExtension() error {
	if ext.Proof == nil {
		return ErrInvalidProof
	}
	return ext.Proof.Validate()
}
