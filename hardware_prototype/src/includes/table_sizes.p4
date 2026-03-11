#pragma once

//--- Match-action table sizes

// Packet tracking direction
#define TABSIZE_SEQ_MATCH 256
#define TABSIZE_ACK_MATCH 256

// Packet fate upon exiting ingress pipeline
#define TABSIZE_INGRESS_EXIT 256

// Forwarding decision based on packet fate and packet headers
#define TABSIZE_IP_MAC_FORWARDING 256
#define TABSIZE_MAC_FORWARDING 256

//--- Register sizes: RTT computation

// // Range tracker table
#define REGWIDTH_RANGE_TRACKER 16
#define REGSIZE_RANGE_TRACKER 65536

// #define REGWIDTH_RANGE_TRACKER 1
// #define REGSIZE_RANGE_TRACKER 2

// // Packet tracker table
#define REGWIDTH_PACKET_TRACKER 16
#define REGSIZE_PACKET_TRACKER 65536

// #define REGWIDTH_PACKET_TRACKER 1
// #define REGSIZE_PACKET_TRACKER 2

// Passive mitigation
#define REGWIDTH_FLOW_TRACKER 16
#define REGSIZE_FLOW_TRACKER 65536
#define REGWIDTH_PREFIX_TRACKER 16
#define REGSIZE_PREFIX_TRACKER 65536

#define REGWIDTH_PREFIX_BLOCKLIST 16
#define REGSIZE_PREFIX_BLOCKLIST 65536

// #define REGWIDTH_FLOW_TRACKER 1
// #define REGSIZE_FLOW_TRACKER 2
// #define REGWIDTH_PREFIX_TRACKER 1
// #define REGSIZE_PREFIX_TRACKER 2

// #define REGWIDTH_PREFIX_BLOCKLIST 1
// #define REGSIZE_PREFIX_BLOCKLIST 2

//--- Register sizes: Active mitigation

// Honeypot prefix state register
#define REGWIDTH_HONEYPOT 8
#define REGSIZE_HONEYPOT 256

// Blacklist prefix registers
#define REGWIDTH_BLACKLIST 8
#define REGSIZE_BLACKLIST 256