import { GeneratedType } from "@cosmjs/proto-signing";
import { EventEpochEnd } from "./types/cosmos/epochs/v1beta1/events";
import { GenesisState } from "./types/cosmos/epochs/v1beta1/genesis";
import { QueryEpochInfosRequest } from "./types/cosmos/epochs/v1beta1/query";
import { EventEpochStart } from "./types/cosmos/epochs/v1beta1/events";
import { EpochInfo } from "./types/cosmos/epochs/v1beta1/genesis";
import { QueryEpochInfosResponse } from "./types/cosmos/epochs/v1beta1/query";
import { QueryCurrentEpochRequest } from "./types/cosmos/epochs/v1beta1/query";
import { QueryCurrentEpochResponse } from "./types/cosmos/epochs/v1beta1/query";

const msgTypes: Array<[string, GeneratedType]>  = [
    ["/cosmos.epochs.v1beta1.EventEpochEnd", EventEpochEnd],
    ["/cosmos.epochs.v1beta1.GenesisState", GenesisState],
    ["/cosmos.epochs.v1beta1.QueryEpochInfosRequest", QueryEpochInfosRequest],
    ["/cosmos.epochs.v1beta1.EventEpochStart", EventEpochStart],
    ["/cosmos.epochs.v1beta1.EpochInfo", EpochInfo],
    ["/cosmos.epochs.v1beta1.QueryEpochInfosResponse", QueryEpochInfosResponse],
    ["/cosmos.epochs.v1beta1.QueryCurrentEpochRequest", QueryCurrentEpochRequest],
    ["/cosmos.epochs.v1beta1.QueryCurrentEpochResponse", QueryCurrentEpochResponse],
    
];

export { msgTypes }