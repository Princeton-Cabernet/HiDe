struct ig_metadata_t {
    IPv4Addr_t src_prefix;
    IPv4Addr_t dst_prefix;
    seq_match_type_t seq_match_type;
    ack_match_type_t ack_match_type;
    seq_validity_type_t seq_validity_type;
    ack_validity_type_t ack_validity_type;
    TCPSeqNum_t expected_ack;
    RTTComputationIngress_t rtt_ingress;
    packet_fate_type_t packet_fate;
    MirrorId_t mirror_session_id;
    handoff_type_t handoff_type;
    bit<16> ingress_port;
}

struct eg_metadata_t {
    packet_fate_type_t packet_fate;
    MirrorId_t mirror_session_id;
    handoff_type_t handoff_type;
    bit<16> ingress_port;
    RTTComputationEgress_t rtt_egress;
}
