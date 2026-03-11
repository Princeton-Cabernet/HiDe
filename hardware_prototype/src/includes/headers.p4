// TM (bridge/mirror) headers
header mirror_h {
    handoff_type_t handoff_type;
}

header mirror_bridged_metadata_h {
    handoff_type_t handoff_type;
    bit<16> ingress_port;
    RTTComputationBridge_t dart_bridge;
    // Timestamp_t ingress_tstamp;
    // rtt_in_type_t rtt_in_type;
    // rtt_status_type_t rtt_status_type;
    // flow_range_verdict_t flow_range_verdict;
    // RangeRecord_t range_record_current;
    // TCPSeqNum_t sub_result_flow_signatures;
}

// Protocol headers
header ethernet_h {
    MacAddr_t dst_addr;
    MacAddr_t src_addr;
    EtherType_t ether_type;
}

header dart_recirc_h {
    // Equal (or lesser) to the IPv4 + TCP header size since we're modifying them
    // 32 bytes
    rtt_in_type_t   recirc_type;            // 1 byte
    rtt_in_type_t   first_packet_type;      // 1 byte
    FlowSignature_t flow_signature_first;   // 4 bytes
    TCPSeqNum_t     packet_eack_first; // 4 bytes
    RangeRecord_t   range_record_current;   // 4 bytes * 3 = 12 bytes
    PacketRecord_t  packet_record_current;  // 4 bytes * 2 = 8 bytes
    Counter8_t      recirc_count_flow;      // 1 byte
    Counter8_t      recirc_count_packet;    // 1 byte
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  dscp_ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    IPv4Addr_t src_addr;
    IPv4Addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<3>  flags_ceu;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header rtt_report_h {   // Modified UDP packet
    // Equal to the TCP header size since we're modifying it
    // 20 bytes
    bit<16>     src_port;       // 2 bytes
    bit<16>     dst_port;       // 2 bytes
    bit<16>     total_length;   // 2 bytes
    bit<16>     checksum;       // 2 bytes
    TCPSeqNum_t ack_no;         // 4 bytes
    Timestamp_t pt_tstamp;      // 4 bytes
    Timestamp_t rtt;            // 4 bytes
}

struct header_t {
    mirror_bridged_metadata_h bridged_md;
    mirror_h mirror_md;
    ethernet_h ethernet;
    dart_recirc_h dart_recirc;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    rtt_report_h rtt_report;
}