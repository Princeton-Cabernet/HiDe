// Control block to determine the fate of the packet upon exiting the ingress pipeline

control Ingress_Exit (
    in header_t hdr,
    inout packet_fate_type_t packet_fate,
    in seq_match_type_t seq_match_type,
    in ack_match_type_t ack_match_type
) {
    action set_packet_fate(packet_fate_type_t pkt_fate){
        packet_fate = pkt_fate;
    }
    
    table tab_ingress_exit {
        size = TABSIZE_INGRESS_EXIT;
        key = {
            seq_match_type: exact;
            ack_match_type: exact;
        }
        actions = { set_packet_fate; }
        const default_action = set_packet_fate( PKT_FATE_NORMAL_EGRESS );
        const entries = {
            ( SEQ_MATCH_INVALID, ACK_MATCH_INVALID ): set_packet_fate( PKT_FATE_DROP );
            ( SEQ_MATCH_MISS, ACK_MATCH_MISS ): set_packet_fate( PKT_FATE_NORMAL_EGRESS );
            ( SEQ_MATCH_HIT, ACK_MATCH_HIT ):   set_packet_fate( PKT_FATE_MIRROR_E2E );
            ( SEQ_MATCH_HIT, ACK_MATCH_MISS ):  set_packet_fate( PKT_FATE_MIRROR_I2E );
            ( SEQ_MATCH_MISS, ACK_MATCH_HIT ):  set_packet_fate( PKT_FATE_MIRROR_I2E );
        }
    }

    apply {
        tab_ingress_exit.apply();
    }
}