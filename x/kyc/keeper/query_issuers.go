package keeper

import (
	"context"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"vnic/x/kyc/types"
)

func (k queryServer) Issuers(ctx context.Context, req *types.QueryIssuersRequest) (*types.QueryIssuersResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var issuers []types.Issuer
	store := runtime.KVStoreAdapter(k.k.storeService.OpenKVStore(ctx))
	issuerStore := prefix.NewStore(store, types.IssuerKey)

	pageRes, err := query.Paginate(issuerStore, req.Pagination, func(key []byte, value []byte) error {
		var issuer types.Issuer
		if err := k.k.cdc.Unmarshal(value, &issuer); err != nil {
			return err
		}
		issuers = append(issuers, issuer)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryIssuersResponse{Issuers: issuers, Pagination: pageRes}, nil
}