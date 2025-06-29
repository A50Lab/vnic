package types

import "cosmossdk.io/collections"

const (
	// ModuleName defines the module name
	ModuleName = "kyc"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// GovModuleName duplicates the gov module's name to avoid a dependency with x/gov.
	// It should be synced with the gov module's name if it is ever changed.
	// See: https://github.com/cosmos/cosmos-sdk/blob/v0.52.0-beta.2/x/gov/types/keys.go#L9
	GovModuleName = "gov"
)

// ParamsKey is the prefix to retrieve all Params
var ParamsKey = collections.NewPrefix("p_kyc")

// IdentityKey is the prefix to retrieve all Identity records
var IdentityKey = collections.NewPrefix("identity")

// KYCLevelKey is the prefix for KYC level mappings by address
var KYCLevelKey = collections.NewPrefix("kyc_level")

// IssuerKey is the prefix for KYC issuer mappings by address
var IssuerKey = collections.NewPrefix("issuer")
