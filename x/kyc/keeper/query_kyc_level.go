package keeper

import (
	"context"

	"vnic/x/kyc/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (q queryServer) KycLevel(ctx context.Context, req *types.QueryKycLevelRequest) (*types.QueryKycLevelResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address cannot be empty")
	}

	// Get KYC level from store
	level, err := q.k.KYCLevels.Get(ctx, req.Address)
	if err != nil {
		return nil, status.Error(codes.NotFound, "KYC level not found for address")
	}

	return &types.QueryKycLevelResponse{
		Level: level,
	}, nil
}
