package types

// DONTCOVER

import (
	"cosmossdk.io/errors"
)

// x/kyc module sentinel errors
var (
	ErrInvalidSigner      = errors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")
	ErrInvalidProof       = errors.Register(ModuleName, 1101, "invalid ZK proof format")
	ErrInvalidKYCLevel    = errors.Register(ModuleName, 1102, "invalid KYC level, must be between 0 and 5")
	ErrIdentityExists     = errors.Register(ModuleName, 1103, "identity already exists")
	ErrIdentityNotFound   = errors.Register(ModuleName, 1104, "identity not found")
	ErrInsufficientKYC    = errors.Register(ModuleName, 1105, "insufficient KYC level for operation")
	ErrProofVerification  = errors.Register(ModuleName, 1106, "ZK proof verification failed")
	ErrInvalidAddress     = errors.Register(ModuleName, 1107, "invalid address")
	ErrInvalidRequest     = errors.Register(ModuleName, 1108, "invalid request")
	ErrInvalidAuthority   = errors.Register(ModuleName, 1109, "invalid authority")
	ErrIssuerNotFound     = errors.Register(ModuleName, 1110, "issuer not found")
	ErrIssuerNotActive    = errors.Register(ModuleName, 1111, "issuer is not active")
	ErrUnauthorized       = errors.Register(ModuleName, 1112, "unauthorized operation")
)
