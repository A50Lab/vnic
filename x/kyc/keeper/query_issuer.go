package keeper

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"vnic/x/kyc/types"
)

func (k queryServer) Issuer(ctx context.Context, req *types.QueryIssuerRequest) (*types.QueryIssuerResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	issuer, err := k.k.Issuers.Get(ctx, req.Address)
	if err != nil {
		return nil, status.Error(codes.NotFound, "issuer not found")
	}

	return &types.QueryIssuerResponse{Issuer: &issuer}, nil
}