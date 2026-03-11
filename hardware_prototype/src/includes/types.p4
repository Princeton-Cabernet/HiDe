#pragma once

// Protocol and packet field types
typedef bit<48> MacAddr_t;
typedef bit<32> IPv4Addr_t;
typedef bit<16> EtherType_t;
const EtherType_t ETHERTYPE_IPV4 = 16w0x0800;
const EtherType_t ETHERTYPE_DART = 16w0x9000;

typedef bit<8> IPProtocol_t;
const IPProtocol_t IP_PROTOCOLS_ICMP = 1;
const IPProtocol_t IP_PROTOCOLS_TCP = 6;
const IPProtocol_t IP_PROTOCOLS_UDP = 17;

typedef bit<8> TCPFlags_t;
const TCPFlags_t TCP_FLAGS_F = 1;
const TCPFlags_t TCP_FLAGS_S = 2;
const TCPFlags_t TCP_FLAGS_R = 4;
const TCPFlags_t TCP_FLAGS_P = 8;
const TCPFlags_t TCP_FLAGS_A = 16;

typedef bit<32> TCPSeqNum_t;
typedef int<32> TCPSeqInt_t;
typedef bit<32> Timestamp_t;

typedef bit<REGWIDTH_RANGE_TRACKER> RangeTrackerWidth_t;
typedef bit<32> FlowSignature_t;

typedef bit<REGWIDTH_PACKET_TRACKER> PacketTrackerWidth_t;
typedef bit<32> PacketSignature_t;

typedef bit<REGWIDTH_FLOW_TRACKER> FlowTrackerWidth_t;
typedef bit<REGWIDTH_PREFIX_TRACKER> PrefixTrackerWidth_t;
typedef bit<32> PrefixSignature_t;

typedef bit<REGWIDTH_PREFIX_BLOCKLIST> PrefixBlockerWidth_t;

typedef bit<8>  Counter8_t;
typedef bit<16> Counter16_t;

typedef bit<4>  Seed4_t;

struct RangeValue_t {
    TCPSeqNum_t right_edge;
    TCPSeqNum_t left_edge;
}

struct RangeRecord_t {
    FlowSignature_t flow_signature;
    RangeValue_t    flow_range;
}

struct PacketRecord_t {
    TCPSeqNum_t expected_ack;
    Timestamp_t timestamp;
}

struct RTTComputationBridge_t {
    Timestamp_t ingress_tstamp;
    rtt_in_type_t rtt_in_type;
    rtt_status_type_t rtt_status_type;
    flow_range_verdict_t flow_range_verdict;
    RangeRecord_t range_record_current;
    TCPSeqNum_t sub_result_flow_signatures;
}

struct RTTComputationIngress_t {
    bool do_flow_signatures_match;

    rtt_in_type_t rtt_in_type;
    rtt_status_type_t rtt_status_type;
    flow_range_verdict_t flow_range_verdict_type;

    RangeRecord_t range_record_current;
    RangeRecord_t range_record_read;

    // PacketRecord_t packet_record_current;
    // PacketRecord_t packet_record_read;
    TCPSeqNum_t    left_edge_computed;

    TCPSeqNum_t sub_result_flow_range_comparison_crcl;
    TCPSeqNum_t sub_result_flow_range_comparison_crrr;
    TCPSeqNum_t sub_result_flow_range_comparison_clrr;
    TCPSeqNum_t sub_result_flow_range_comparison_crrl;
    TCPSeqNum_t sub_result_flow_signatures;

    RangeTrackerWidth_t rangetracker_index;
    // PacketTrackerWidth_t packettracker_index;

    // FlowSignature_t   flow_signature;
    // PacketSignature_t packet_signature;

    bool recirculate_flow_record;
}

struct RTTComputationEgress_t {
    rtt_in_type_t rtt_in_type;
    rtt_status_type_t rtt_status_type;
    flow_range_verdict_t flow_range_verdict_type;

    Counter16_t counter_seq_pkts;
    Counter16_t counter_recirc_pkts;
    Counter8_t  counter_ack_pkts;

    Timestamp_t ingress_tstamp;

    RangeRecord_t  range_record_current;
    PacketRecord_t packet_record_current;

    bool do_packet_signatures_match;
    bool do_packet_expected_acks_match;

    bool recirculate_flow_record;
    bool recirculate_packet_record;

    bool dart_recirc_valid;

    PacketTrackerWidth_t packettracker_index;

    TCPSeqNum_t sub_result_flow_signatures;
    TCPSeqNum_t sub_result_packet_signatures;
    TCPSeqNum_t sub_result_packet_expected_acks;
    TCPSeqNum_t sub_result_eack_comparison_right;
    TCPSeqNum_t sub_result_eack_comparison_left;
    Timestamp_t sampled_rtt;
}