// Control block to compute eACK/ACK and validate for SEQ/ACK processing

#define TCP_PAYLOAD_SIZE_TAB_FULL 16384
#define TCP_PAYLOAD_SIZE_TAB_SHORT 16

control Validation (
    in header_t hdr,
    in seq_match_type_t seq_match_type,
    in ack_match_type_t ack_match_type,
    inout seq_validity_type_t seq_validity_type,
    inout ack_validity_type_t ack_validity_type,
    inout TCPSeqNum_t expected_ack
) {
    // TCPSeqNum_t ipv4_hdr_len   = 32w0;
    // TCPSeqNum_t tcp_hdr_len    = 32w0;
    // TCPSeqNum_t ipv4_total_len = 32w0;
    // TCPSeqNum_t total_hdr_len  = 32w0;
    TCPSeqNum_t payload_size   = 32w0;

    action no_action() {}

    // TCP payload length computation using a lookup table: Works for common values of IPv4 and TCP header lengths
    action act_set_tcp_payload_size(TCPSeqNum_t lookup_payload_size) {
        payload_size = lookup_payload_size;
    }
    table tab_determine_tcp_payload_size {
        const size = TCP_PAYLOAD_SIZE_TAB_FULL;
        // const size = TCP_PAYLOAD_SIZE_TAB_SHORT;
        key = {
            hdr.ipv4.ihl: exact;
            hdr.ipv4.total_len: exact;
            hdr.tcp.data_offset: exact;
        }
        actions = { act_set_tcp_payload_size; }
        const default_action = act_set_tcp_payload_size( 32w0 );
        const entries = {
            // #include "table_entries/entries_determine_tcp_payload_size__short.p4inc"
            #include "table_entries/entries_determine_tcp_payload_size.p4inc"
        }
    }

    // action load_ipv4_hdr_len() {
    //     // ipv4_hdr_len[5:2] = hdr.ipv4.ihl;
    //     @in_hash { ipv4_hdr_len = 26w0 ++ hdr.ipv4.ihl ++ 2w0; }
    // }

    // action load_tcp_hdr_len() {
    //     // tcp_hdr_len[5:2] = hdr.tcp.data_offset;
    //     @in_hash { tcp_hdr_len = 26w0 ++ hdr.tcp.data_offset ++ 2w0; }
    // }

    // action load_ipv4_total_len() {
    //     // ipv4_total_len[15:0] = hdr.ipv4.total_len;
    //     @in_hash { ipv4_total_len = 16w0 ++ hdr.ipv4.total_len; }
    // }

    // action compute_total_hdr_len() {
    //     @in_hash { total_hdr_len = ipv4_hdr_len + tcp_hdr_len; }
    // }

    // action compute_payload_len() {
    //     @in_hash { payload_size = ipv4_total_len - total_hdr_len; }
    // }

    action compute_expected_ack() {
        @in_hash { expected_ack = hdr.tcp.seq_no + payload_size; }
    }

    action seq_validity_hit() {
        seq_validity_type = SEQ_VALIDITY_HIT;
    }

    action seq_validity_miss() {
        seq_validity_type = SEQ_VALIDITY_MISS;
    }

    action ack_validity_hit() {
        ack_validity_type = ACK_VALIDITY_HIT;
    }

    action ack_validity_miss() {
        ack_validity_type = ACK_VALIDITY_MISS;
    }

    // Register<bit<32>, bit<16>>(65536) counter_packet_sizes;
    // RegisterAction<bit<32>, bit<16>, bit<32>>(counter_packet_sizes) count_packet_size = {
    //     void apply(inout bit<32> mem_cell, out bit<32> ret_val) {
    //         mem_cell = mem_cell + 1;
    //         ret_val = mem_cell;
    //     } };
    // action act_count_packet_size() {
    //     count_packet_size.execute(payload_size);
    // }

    apply {

        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            // Method 1: Compute TCP payload size
            // load_ipv4_hdr_len();
            // load_tcp_hdr_len();
            // load_ipv4_total_len();
            // compute_total_hdr_len();
            // compute_payload_len();
            // act_count_packet_size();

            // Method 2: Lookup TCP payload size
            tab_determine_tcp_payload_size.apply();
            // act_count_packet_size();

            // Compute expected ACK number
            compute_expected_ack();
        }

        if ((seq_match_type == SEQ_MATCH_HIT)
                && (hdr.tcp.rst == 1w0)
                && (hdr.tcp.syn == 1w0)
                && (hdr.tcp.fin == 1w0)
                && (payload_size > 32w0)) {
            seq_validity_hit();
        } else {
            seq_validity_miss();
        }

        if ((ack_match_type == ACK_MATCH_HIT)
                && (hdr.tcp.ack == 1w1)
                && (hdr.tcp.rst == 1w0)
                && (hdr.tcp.syn == 1w0)
                && (hdr.tcp.fin == 1w0)) {
            ack_validity_hit();
        } else {
            ack_validity_miss();
        }

        if (seq_validity_type == SEQ_VALIDITY_HIT) {
            compute_expected_ack();
        } else {
            expected_ack = NULL;
        }
    }
}