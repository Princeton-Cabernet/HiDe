// Control block to determine whether this packet is being monitored
// Determines the following:
//      (1) SEQ direction monitored: True/False
//      (2) ACK direction monitored: True/False

control Monitoring_Status (
    in header_t hdr,
    inout seq_match_type_t seq_match_type,
    inout ack_match_type_t ack_match_type
) {
    // SEQ direction match
    action seq_match_hit()  { seq_match_type = SEQ_MATCH_HIT; }
    action seq_match_miss() { seq_match_type = SEQ_MATCH_MISS; }

    table tab_seq_match {
        size = TABSIZE_SEQ_MATCH;
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
            hdr.tcp.src_port:  range;
            hdr.tcp.dst_port:  range;
        }
        actions = { seq_match_hit; @defaultonly seq_match_miss; }
        const default_action = seq_match_miss();
    }

    // ACK direction match
    action ack_match_hit()  { ack_match_type = ACK_MATCH_HIT; }
    action ack_match_miss() { ack_match_type = ACK_MATCH_MISS; }

    table tab_ack_match {
        size = TABSIZE_ACK_MATCH;
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
            hdr.tcp.src_port:  range;
            hdr.tcp.dst_port:  range;
        }
        actions = { ack_match_hit; @defaultonly ack_match_miss; }
        const default_action = ack_match_miss();
    }

    action act_set_matches_to_misses() {
        seq_match_type = SEQ_MATCH_MISS;
        ack_match_type = ACK_MATCH_MISS;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            tab_seq_match.apply();
            tab_ack_match.apply();
        } else {
            act_set_matches_to_misses();
        }
    }
}