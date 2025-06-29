import { GeneratedType } from "@cosmjs/proto-signing";
import { CounterpartyInfo } from "./types/ibc/core/client/v2/counterparty";
import { QueryConfigResponse } from "./types/ibc/core/client/v2/query";
import { MsgRegisterCounterpartyResponse } from "./types/ibc/core/client/v2/tx";
import { MsgUpdateClientConfig } from "./types/ibc/core/client/v2/tx";
import { QueryCounterpartyInfoRequest } from "./types/ibc/core/client/v2/query";
import { QueryCounterpartyInfoResponse } from "./types/ibc/core/client/v2/query";
import { GenesisState } from "./types/ibc/core/client/v2/genesis";
import { Config } from "./types/ibc/core/client/v2/config";
import { GenesisCounterpartyInfo } from "./types/ibc/core/client/v2/genesis";
import { QueryConfigRequest } from "./types/ibc/core/client/v2/query";
import { MsgRegisterCounterparty } from "./types/ibc/core/client/v2/tx";
import { MsgUpdateClientConfigResponse } from "./types/ibc/core/client/v2/tx";

const msgTypes: Array<[string, GeneratedType]>  = [
    ["/ibc.core.client.v2.CounterpartyInfo", CounterpartyInfo],
    ["/ibc.core.client.v2.QueryConfigResponse", QueryConfigResponse],
    ["/ibc.core.client.v2.MsgRegisterCounterpartyResponse", MsgRegisterCounterpartyResponse],
    ["/ibc.core.client.v2.MsgUpdateClientConfig", MsgUpdateClientConfig],
    ["/ibc.core.client.v2.QueryCounterpartyInfoRequest", QueryCounterpartyInfoRequest],
    ["/ibc.core.client.v2.QueryCounterpartyInfoResponse", QueryCounterpartyInfoResponse],
    ["/ibc.core.client.v2.GenesisState", GenesisState],
    ["/ibc.core.client.v2.Config", Config],
    ["/ibc.core.client.v2.GenesisCounterpartyInfo", GenesisCounterpartyInfo],
    ["/ibc.core.client.v2.QueryConfigRequest", QueryConfigRequest],
    ["/ibc.core.client.v2.MsgRegisterCounterparty", MsgRegisterCounterparty],
    ["/ibc.core.client.v2.MsgUpdateClientConfigResponse", MsgUpdateClientConfigResponse],
    
];

export { msgTypes }