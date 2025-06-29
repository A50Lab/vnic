import { GeneratedType } from "@cosmjs/proto-signing";
import { MsgRecvPacket } from "./types/ibc/core/channel/v2/tx";
import { MsgRecvPacketResponse } from "./types/ibc/core/channel/v2/tx";
import { Packet } from "./types/ibc/core/channel/v2/packet";
import { QueryPacketAcknowledgementRequest } from "./types/ibc/core/channel/v2/query";
import { QueryPacketAcknowledgementsRequest } from "./types/ibc/core/channel/v2/query";
import { QueryUnreceivedAcksRequest } from "./types/ibc/core/channel/v2/query";
import { QueryUnreceivedAcksResponse } from "./types/ibc/core/channel/v2/query";
import { QueryPacketAcknowledgementResponse } from "./types/ibc/core/channel/v2/query";
import { RecvPacketResult } from "./types/ibc/core/channel/v2/packet";
import { QueryPacketCommitmentsRequest } from "./types/ibc/core/channel/v2/query";
import { QueryPacketReceiptRequest } from "./types/ibc/core/channel/v2/query";
import { QueryPacketReceiptResponse } from "./types/ibc/core/channel/v2/query";
import { MsgSendPacket } from "./types/ibc/core/channel/v2/tx";
import { MsgTimeout } from "./types/ibc/core/channel/v2/tx";
import { MsgTimeoutResponse } from "./types/ibc/core/channel/v2/tx";
import { MsgAcknowledgementResponse } from "./types/ibc/core/channel/v2/tx";
import { QueryNextSequenceSendResponse } from "./types/ibc/core/channel/v2/query";
import { QueryUnreceivedPacketsRequest } from "./types/ibc/core/channel/v2/query";
import { PacketSequence } from "./types/ibc/core/channel/v2/genesis";
import { MsgSendPacketResponse } from "./types/ibc/core/channel/v2/tx";
import { MsgAcknowledgement } from "./types/ibc/core/channel/v2/tx";
import { GenesisState } from "./types/ibc/core/channel/v2/genesis";
import { QueryNextSequenceSendRequest } from "./types/ibc/core/channel/v2/query";
import { QueryPacketCommitmentRequest } from "./types/ibc/core/channel/v2/query";
import { Acknowledgement } from "./types/ibc/core/channel/v2/packet";
import { PacketState } from "./types/ibc/core/channel/v2/genesis";
import { Payload } from "./types/ibc/core/channel/v2/packet";
import { QueryPacketCommitmentResponse } from "./types/ibc/core/channel/v2/query";
import { QueryPacketCommitmentsResponse } from "./types/ibc/core/channel/v2/query";
import { QueryPacketAcknowledgementsResponse } from "./types/ibc/core/channel/v2/query";
import { QueryUnreceivedPacketsResponse } from "./types/ibc/core/channel/v2/query";

const msgTypes: Array<[string, GeneratedType]>  = [
    ["/ibc.core.channel.v2.MsgRecvPacket", MsgRecvPacket],
    ["/ibc.core.channel.v2.MsgRecvPacketResponse", MsgRecvPacketResponse],
    ["/ibc.core.channel.v2.Packet", Packet],
    ["/ibc.core.channel.v2.QueryPacketAcknowledgementRequest", QueryPacketAcknowledgementRequest],
    ["/ibc.core.channel.v2.QueryPacketAcknowledgementsRequest", QueryPacketAcknowledgementsRequest],
    ["/ibc.core.channel.v2.QueryUnreceivedAcksRequest", QueryUnreceivedAcksRequest],
    ["/ibc.core.channel.v2.QueryUnreceivedAcksResponse", QueryUnreceivedAcksResponse],
    ["/ibc.core.channel.v2.QueryPacketAcknowledgementResponse", QueryPacketAcknowledgementResponse],
    ["/ibc.core.channel.v2.RecvPacketResult", RecvPacketResult],
    ["/ibc.core.channel.v2.QueryPacketCommitmentsRequest", QueryPacketCommitmentsRequest],
    ["/ibc.core.channel.v2.QueryPacketReceiptRequest", QueryPacketReceiptRequest],
    ["/ibc.core.channel.v2.QueryPacketReceiptResponse", QueryPacketReceiptResponse],
    ["/ibc.core.channel.v2.MsgSendPacket", MsgSendPacket],
    ["/ibc.core.channel.v2.MsgTimeout", MsgTimeout],
    ["/ibc.core.channel.v2.MsgTimeoutResponse", MsgTimeoutResponse],
    ["/ibc.core.channel.v2.MsgAcknowledgementResponse", MsgAcknowledgementResponse],
    ["/ibc.core.channel.v2.QueryNextSequenceSendResponse", QueryNextSequenceSendResponse],
    ["/ibc.core.channel.v2.QueryUnreceivedPacketsRequest", QueryUnreceivedPacketsRequest],
    ["/ibc.core.channel.v2.PacketSequence", PacketSequence],
    ["/ibc.core.channel.v2.MsgSendPacketResponse", MsgSendPacketResponse],
    ["/ibc.core.channel.v2.MsgAcknowledgement", MsgAcknowledgement],
    ["/ibc.core.channel.v2.GenesisState", GenesisState],
    ["/ibc.core.channel.v2.QueryNextSequenceSendRequest", QueryNextSequenceSendRequest],
    ["/ibc.core.channel.v2.QueryPacketCommitmentRequest", QueryPacketCommitmentRequest],
    ["/ibc.core.channel.v2.Acknowledgement", Acknowledgement],
    ["/ibc.core.channel.v2.PacketState", PacketState],
    ["/ibc.core.channel.v2.Payload", Payload],
    ["/ibc.core.channel.v2.QueryPacketCommitmentResponse", QueryPacketCommitmentResponse],
    ["/ibc.core.channel.v2.QueryPacketCommitmentsResponse", QueryPacketCommitmentsResponse],
    ["/ibc.core.channel.v2.QueryPacketAcknowledgementsResponse", QueryPacketAcknowledgementsResponse],
    ["/ibc.core.channel.v2.QueryUnreceivedPacketsResponse", QueryUnreceivedPacketsResponse],
    
];

export { msgTypes }