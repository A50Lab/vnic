package ante

import (
	"vnic/x/kyc/keeper"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
)

// HandlerOptions are the options required for constructing a default SDK AnteHandler.
type HandlerOptions struct {
	ante.HandlerOptions
	KYCKeeper keeper.Keeper
}

// NewAnteHandler returns an AnteHandler that checks and increments sequence
// numbers, checks signatures & account numbers, and deducts fees from the first
// signer, and also enforces KYC requirements.
func NewAnteHandler(options HandlerOptions) sdk.AnteHandler {
	if options.AccountKeeper == nil {
		panic("account keeper is required for ante builder")
	}

	if options.BankKeeper == nil {
		panic("bank keeper is required for ante builder")
	}

	if options.SignModeHandler == nil {
		panic("sign mode handler is required for ante builder")
	}

	// Create KYC ante handler
	kycAnteHandler := NewKYCAnteHandler(options.KYCKeeper)

	// Create standard Cosmos SDK ante handlers
	anteDecorators := []sdk.AnteDecorator{
		ante.NewSetUpContextDecorator(), // outermost AnteDecorator. SetUpContext must be called first
		ante.NewExtensionOptionsDecorator(options.ExtensionOptionChecker),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		ante.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.TxFeeChecker),
		ante.NewSetPubKeyDecorator(options.AccountKeeper), // SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		ante.NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		NewKYCDecorator(kycAnteHandler), // Add KYC validation as the final step
	}

	return sdk.ChainAnteDecorators(anteDecorators...)
}

// KYCDecorator wraps the KYC ante handler to conform to the AnteDecorator interface
type KYCDecorator struct {
	kycHandler KYCAnteHandler
}

// NewKYCDecorator creates a new KYC decorator
func NewKYCDecorator(kycHandler KYCAnteHandler) KYCDecorator {
	return KYCDecorator{
		kycHandler: kycHandler,
	}
}

// AnteHandle implements AnteDecorator interface for KYC validation
func (k KYCDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	return k.kycHandler.AnteHandle(ctx, tx, simulate, next)
}
