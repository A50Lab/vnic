import { GeneratedType } from "@cosmjs/proto-signing";
import { MsgUpdateParams } from "./types/vnic/vnic/v1/tx";
import { MsgUpdateParamsResponse } from "./types/vnic/vnic/v1/tx";
import { QueryParamsRequest } from "./types/vnic/vnic/v1/query";
import { GenesisState } from "./types/vnic/vnic/v1/genesis";
import { Params } from "./types/vnic/vnic/v1/params";
import { QueryParamsResponse } from "./types/vnic/vnic/v1/query";

const msgTypes: Array<[string, GeneratedType]>  = [
    ["/vnic.vnic.v1.MsgUpdateParams", MsgUpdateParams],
    ["/vnic.vnic.v1.MsgUpdateParamsResponse", MsgUpdateParamsResponse],
    ["/vnic.vnic.v1.QueryParamsRequest", QueryParamsRequest],
    ["/vnic.vnic.v1.GenesisState", GenesisState],
    ["/vnic.vnic.v1.Params", Params],
    ["/vnic.vnic.v1.QueryParamsResponse", QueryParamsResponse],
    
];

export { msgTypes }