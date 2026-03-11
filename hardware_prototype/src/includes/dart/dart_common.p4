#define TCP_PAYLOAD_SIZE_TAB_FULL 16384
#define TCP_PAYLOAD_SIZE_TAB_SHORT 16

#define NULL 0

#define FLOW_TABLE_SIGN_WSZ 32
#define PACKET_TABLE_SIGN_WSZ 32

#define FLOW_TABLE_STAGE_SIZE 65536
#define PACKET_TABLE_STAGE_SIZE 65536
// Log base 2 of the previous values
#define FLOW_TABLE_ADDR_WSZ 16
#define PACKET_TABLE_ADDR_WSZ 16

#define CRC_POLY_0 0x8005
#define CRC_POLY_1 0x0589
#define CRC_POLY_2 0x3D65
#define CRC_POLY_3 32w0x1021
#define CRC_POLY_4 0x8BB7
#define CRC_POLY_5 0xA097

// Typedefs
typedef bit<FLOW_TABLE_ADDR_WSZ>   ft_addr_wsz;
typedef bit<PACKET_TABLE_ADDR_WSZ> pt_addr_wsz;

typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
// typedef bit<128> ipv6_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_PRTT = 16w0x9000; // Repurposing "LOOP" ethertype 9000 for P4RTT recirculation

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOL_ICMP = 1;
const ip_protocol_t IP_PROTOCOL_TCP  = 6;
const ip_protocol_t IP_PROTOCOL_UDP  = 17;

typedef bit<8>   packet_type_t;
typedef bit<16>  tcp_port_t;
typedef bit<32>  mr_edge_t;
typedef bit<32>  eack_t;
typedef bit<32>  timestamp_t;
typedef bit<32>  flow_sign_t;
typedef bit<8>   recirc_count_t;
typedef bit<16>  table_index_t;

const recirc_count_t FLOW_TABLE_MAX_RECIRC   = 3;
const recirc_count_t PACKET_TABLE_MAX_RECIRC = 3;

// Incoming packet types
const packet_type_t PKT_TYPE_TCP_PIN = 1; // TCP Packet In
const packet_type_t PKT_TYPE_FTS_PIN = 2; // TCP Copy Packet In (SEQ direction because ACK direction already processed)
const packet_type_t PKT_TYPE_FTI_PIN = 3; // FT Insert Packet In (comes in with precomputed left and right edges)
const packet_type_t PKT_TYPE_FTE_PIN = 4; // FT Evicted In
const packet_type_t PKT_TYPE_FTE_PRE = 5; // PKT_TYPE_FTE_PIN with pending PT processing
const packet_type_t PKT_TYPE_PTE_PIN = 6; // PT Evicted In
const packet_type_t PKT_TYPE_RTT_OUT = 7; // RTT Report Out

// TCP packet direction match types (before validity check)
const packet_type_t SQPM_SEQ = 16; // TCP SEQ Priority Table Match: SEQ Direction
const packet_type_t SQPM_ACK = 17; // TCP SEQ Priority Table Match: ACK Direction
const packet_type_t AKPM_SEQ = 18; // TCP ACK Priority Table Match: SEQ Direction
const packet_type_t AKPM_ACK = 19; // TCP ACK Priority Table Match: ACK Direction

// Valid TCP packet direction match types
const packet_type_t PKT_TYPE_TCP_BTH = 32;  // TCP Matches Both Directions
const packet_type_t PKT_TYPE_TCP_SEQ = 33;  // TCP Matches Only SEQ Direction
const packet_type_t PKT_TYPE_TCP_ACK = 34;  // TCP Matches Only ACK Direction

const bit<4> seed_stage_0 = 7;
const bit<4> seed_stage_1 = 3;
// const bit<4> seed_stage_2 = 11;

const bit<4> seed_flow_signature   = 5;
const bit<4> seed_packet_signature = 11;

const packet_type_t STATUS_MR_NULL      = 1;
const packet_type_t STATUS_MR_PROCEED   = 2;
const packet_type_t STATUS_MR_COLLAPSED = 3;

// Key + Value types
struct flow_record_keyval_t {
    flow_sign_t flow_sign;
    mr_edge_t   right_edge;
    mr_edge_t   left_edge;
}
struct packet_record_keyval_t {
    eack_t        eack;
    timestamp_t   timestamp;
}

// Key types
struct flow_record_key_t {
    flow_sign_t flow_sign;
}
struct packet_record_key_t {
    eack_t eack;
}

// Value type
struct flow_record_val_t {
    mr_edge_t   right_edge;
    mr_edge_t   left_edge;
}

header p4rtt_recirc_h {
    // Equal (or lesser) to the IPv4 + TCP header size since we're modifying them
    // 32 bytes without table_index_t
    packet_type_t          recirc_type;          // 1 byte
    packet_type_t          first_packet_type;    // 1 byte
    flow_record_key_t      first_flow_rec;       // 4 bytes
    packet_record_key_t    first_packet_rec;     // 4 bytes
    flow_record_keyval_t   curr_flow_rec;        // 4 bytes * 3 = 12 bytes
    packet_record_keyval_t curr_packet_rec;      // 4 bytes * 2 = 8 bytes
    recirc_count_t         recirc_count_flow;    // 1 byte
    recirc_count_t         recirc_count_packet;  // 1 byte
    // table_index_t          first_packet_rec_index; // 2 bytes
}

header rtt_report_h {   // Modified UDP packet
    // Equal to the TCP header size since we're modifying it
    // 20 bytes
    bit<16>     src_port;       // 2 bytes
    bit<16>     dst_port;       // 2 bytes
    bit<16>     total_length;   // 2 bytes
    bit<16>     checksum;       // 2 bytes
    eack_t      ack_no;         // 4 bytes
    timestamp_t pt_tstamp;      // 4 bytes
    timestamp_t rtt;            // 4 bytes
}

@flexible
header bridged_md_h {

    bit<32> ingress_tstamp;
    
    packet_type_t packet_type;
    packet_type_t packet_status;
    packet_type_t ft_update_status;
    
    flow_record_keyval_t curr_flow_rec;

    bit<32> sub_result_flow_signatures;
}

struct dart_ig_metadata_t {

    bit<32> ingress_tstamp;

    packet_type_t seq_match_packet_type;
    packet_type_t ack_match_packet_type;

    // bit<32> tot_hdr_len;
    // bit<32> ip_pkt_len;
    bit<32> payload_size;

    packet_type_t packet_type;
    packet_type_t ft_update_status;
    packet_type_t packet_status;

    flow_record_keyval_t curr_flow_rec;
    flow_record_val_t    read_flow_rec;

    mr_edge_t           comp_left_edge;

    bool do_flow_signatures_match;

    ft_addr_wsz ft_stage_0_index;

    bit<32> sub_result_mr_comparison_crcl;
    bit<32> sub_result_mr_comparison_crrr;
    bit<32> sub_result_mr_comparison_clrr;
    bit<32> sub_result_mr_comparison_crrl;
    bit<32> sub_result_flow_signatures;

    bridged_md_h bridged_md;
}