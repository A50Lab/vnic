package keeper

import (
	"context"
	"encoding/json"

	"vnic/x/kyc/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (q queryServer) Identity(ctx context.Context, req *types.QueryIdentityRequest) (*types.QueryIdentityResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "identity ID cannot be empty")
	}

	// Get identity from store
	identityJSON, err := q.k.Identities.Get(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "identity not found")
	}

	// Parse JSON identity data
	var identity types.Identity
	if err := json.Unmarshal([]byte(identityJSON), &identity); err != nil {
		return nil, status.Error(codes.Internal, "failed to parse identity data")
	}

	return &types.QueryIdentityResponse{
		Id:         identity.ID,
		State:      identity.State,
		KycLevel:   identity.KYCLevel,
		Attributes: identity.Attributes,
		ClaimsRoot: identity.ClaimsRoot,
		RevRoot:    identity.RevRoot,
		RootsRoot:  identity.RootsRoot,
	}, nil
}
