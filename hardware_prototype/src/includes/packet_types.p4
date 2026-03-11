#pragma once

typedef bit<8> pkt_type_t;

// TCP SEQ direction match
typedef pkt_type_t seq_match_type_t;
const seq_match_type_t SEQ_MATCH_INVALID = 0x0;   // Invalid
const seq_match_type_t SEQ_MATCH_HIT     = 0x1;   // TCP SEQ Table: Hit
const seq_match_type_t SEQ_MATCH_MISS    = 0x2;   // TCP SEQ Table: Miss

// TCP ACK direction match
typedef pkt_type_t ack_match_type_t;
const ack_match_type_t ACK_MATCH_INVALID = 0x0;   // Invalid
const ack_match_type_t ACK_MATCH_HIT     = 0x3;   // TCP ACK Table: Hit
const ack_match_type_t ACK_MATCH_MISS    = 0x4;   // TCP ACK Table: Miss

// TCP SEQ valid match
typedef pkt_type_t seq_validity_type_t;
const seq_validity_type_t SEQ_VALIDITY_INVALID = 0x0;   // Invalid
const seq_validity_type_t SEQ_VALIDITY_HIT     = 0x5;   // TCP SEQ valid
const seq_validity_type_t SEQ_VALIDITY_MISS    = 0x6;   // TCP SEQ invalid

// TCP ACK valid match
typedef pkt_type_t ack_validity_type_t;
const ack_validity_type_t ACK_VALIDITY_INVALID = 0x0;   // Invalid
const ack_validity_type_t ACK_VALIDITY_HIT     = 0x7;   // TCP ACK valid
const ack_validity_type_t ACK_VALIDITY_MISS    = 0x8;   // TCP ACK invalid

// TCP RTT computation types
typedef pkt_type_t rtt_in_type_t;
const rtt_in_type_t RTT_IN_TYPE_INVALID = 0x0;  // Invalid
const rtt_in_type_t RTT_IN_TYPE_NONE    = 0x11; // TCP Packet In
const rtt_in_type_t RTT_IN_TYPE_TCP_PIN = 0x12; // TCP Packet In
const rtt_in_type_t RTT_IN_TYPE_FTS_PIN = 0x13; // TCP Copy Packet In (SEQ direction because ACK direction already processed)
const rtt_in_type_t RTT_IN_TYPE_FTI_PIN = 0x14; // FT Insert Packet In (comes in with precomputed left and right edges)
const rtt_in_type_t RTT_IN_TYPE_FTE_PIN = 0x15; // FT Evicted In
const rtt_in_type_t RTT_IN_TYPE_FTE_PRE = 0x16; // PKT_TYPE_FTE_PIN with pending PT processing
const rtt_in_type_t RTT_IN_TYPE_PTE_PIN = 0x17; // PT Evicted In
const rtt_in_type_t RTT_IN_TYPE_RTT_OUT = 0x18; // RTT Report Out

typedef pkt_type_t rtt_status_type_t;
const rtt_status_type_t RTT_STATUS_INVALID            = 0x0;    // Invalid
const rtt_status_type_t RTT_STATUS_FIRST_RANGE_RECIRC = 0x21;
const rtt_status_type_t RTT_STATUS_PACKET_RECIRC      = 0x22;
const rtt_status_type_t RTT_STATUS_SEQ_VALID          = 0x23;
const rtt_status_type_t RTT_STATUS_ACK_VALID          = 0x24;
const rtt_status_type_t RTT_STATUS_PACKET_RECIRC_AND_FLOW_SIGNATURES_MATCH = 0x25;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_WRAPPED_AROUND = 0x26;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND  = 0x27;
const rtt_status_type_t RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH = 0x28;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_WRAPAROUND_ADJUSTED = 0x29;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_FULL_OVERLAP = 0x2A;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_EXTENSION = 0x2B;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_PARTIAL_OVERLAP = 0x2C;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_HOLE = 0x2D;
const rtt_status_type_t RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK = 0x2E;
const rtt_status_type_t RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK = 0x2F;
const rtt_status_type_t RTT_STATUS_RANGE_RECORD_RECIRC_SETUP    = 0x31;
const rtt_status_type_t RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED = 0x32;
const rtt_status_type_t RTT_STATUS_PACKET_RECORD_VALID          = 0x33;
const rtt_status_type_t RTT_STATUS_FTI_PIN_RECIRC_SETUP         = 0x34;
const rtt_status_type_t RTT_STATUS_SEQ_VALID_PACKET_PROCEED     = 0x35;
const rtt_status_type_t RTT_STATUS_ACK_VALID_PACKET_PROCEED     = 0x36;
const rtt_status_type_t RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH = 0x37;

// Flow range verdicts
typedef pkt_type_t flow_range_verdict_t;
const flow_range_verdict_t FLOW_RANGE_VERDICT_INVALID   = 0x0;
const flow_range_verdict_t FLOW_RANGE_VERDICT_NONE      = 0x41;
const flow_range_verdict_t FLOW_RANGE_VERDICT_PROCEED   = 0x42;
const flow_range_verdict_t FLOW_RANGE_VERDICT_COLLAPSED = 0x43;

// Passive mitigation attack state types
typedef pkt_type_t attack_status_type_t;
const attack_status_type_t ATTACK_STATUS_TYPE_INVALID   = 0x0;   // Invalid
const attack_status_type_t ATTACK_STATUS_TYPE_NOATTACK  = 0x51;  // No attack
const attack_status_type_t ATTACK_STATUS_TYPE_SUSPECTED = 0x52;  // Attack suspected
const attack_status_type_t ATTACK_STATUS_TYPE_CONFIRMED = 0x53;  // Attack confirmed
// #define ATTACK_STATUS_TYPE_INVALID 8w0x0     // Invalid
// #define ATTACK_STATUS_TYPE_NOATTACK 8w0x51   // No attack
// #define ATTACK_STATUS_TYPE_SUSPECTED 8w0x52  // Attack suspected
// #define ATTACK_STATUS_TYPE_CONFIRMED 8w0x53  // Attack confirmed

// Packet fate types
typedef pkt_type_t packet_fate_type_t;
const packet_fate_type_t PKT_FATE_INVALID            = 0x60;    // Invalid
const packet_fate_type_t PKT_FATE_NORMAL_EGRESS      = 0x61;   // Set an egress port and continue processing
const packet_fate_type_t PKT_FATE_REPORT_EGRESS      = 0x62;   // Set the report egress port
const packet_fate_type_t PKT_FATE_RECIRCULATE        = 0x63;   // Set recirculation port and continue processing
const packet_fate_type_t PKT_FATE_DROP               = 0x64;   // Drop packet
const packet_fate_type_t PKT_FATE_BLACKLIST          = 0x65;
const packet_fate_type_t PKT_FATE_MIRROR_COMPUTE_RTT_AND_EGRESS = 0x66;
const packet_fate_type_t PKT_FATE_MIRROR_RTTACK_AND_EGRESS      = 0x67;
// const packet_fate_type_t PKT_FATE_MIRROR_REPORT_AND_EGRESS      = 0x68;
const packet_fate_type_t PKT_FATE_MIRROR_HONEYPOT_AND_EGRESS    = 0x69;
const packet_fate_type_t PKT_FATE_BLACKLIST_AND_DROP            = 0x6A;
const packet_fate_type_t PKT_FATE_BRIDGE_TO_EGRESS_AND_EGRESS   = 0x6B;
const packet_fate_type_t PKT_FATE_BYPASS_EGRESS_AND_EGRESS      = 0x6C;
const packet_fate_type_t PKT_FATE_BYPASS_EGRESS_AND_REPORT_EGRESS = 0x6D;

typedef pkt_type_t handoff_type_t;
const handoff_type_t HANDOFF_TYPE_INVALID = 0x70;
const handoff_type_t HANDOFF_TYPE_BRIDGE  = 0x71;
const handoff_type_t HANDOFF_TYPE_BRIDGE_REPORT = 0x72;
const handoff_type_t HANDOFF_TYPE_MIRROR_COMPUTE_RTT = 0x73;
const handoff_type_t HANDOFF_TYPE_MIRROR_REPORT_RTT  = 0x74;
const handoff_type_t HANDOFF_TYPE_MIRROR_HONEYPOT    = 0x75;
