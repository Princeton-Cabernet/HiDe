#include <core.p4>
#if __TARGET_TOFINO__ == 1
#include <tna.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#endif

#include "includes/definitions.p4"
#include "includes/ports.p4"
// #include "includes/ports_cabino4.p4"
#include "includes/table_sizes.p4"
#include "includes/packet_types.p4"
#include "includes/types.p4"

#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parsers.p4"

#include "includes/monitoring_status.p4"
#include "includes/validation.p4"
#include "includes/rtt_computation_ingress.p4"
#include "includes/rtt_computation_egress.p4"
// #include "includes/dart/dart.p4"
#include "includes/passive_mitigation.p4"
// #include "includes/active_mitigation.p4"
#include "includes/egress_handoff.p4"
// #include "includes/access_control.p4"
#include "includes/basic_forwarding.p4"

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    Monitoring_Status()         monitoring_status;
    Validation()                validation;
    RTT_Computation_Ingress()   rtt_computation_ingress;
    Passive_Mitigation()        passive_mitigation;
    // Active_Mitigation()         active_mitigation;
    Egress_Handoff()            egress_handoff;
    // Access_Control()            access_control;
    Basic_Forwarding()          basic_forwarding;

    apply {

        // Extract ingress timestamp
        // Timestamp_t ingress_timestamp = ig_intr_md.ingress_mac_tstamp[31:0];
        Timestamp_t ingress_timestamp = hdr.ethernet.dst_addr[31:0];
        ig_md.ingress_port = 7w0 ++ ig_intr_md.ingress_port;
        
        // Deal with zero values because they can cause confusion
        if (ingress_timestamp == 0x0) {
            ingress_timestamp = 0x1;
        }
        // if (hdr.tcp.isValid() && hdr.tcp.seq_no == 0) {
        //     hdr.tcp.seq_no = 1; // Todo: Extract seq number in ig_md field then use it everywhere
        // }
        // if (hdr.tcp.isValid() && hdr.tcp.ack_no == 0) {
        //     hdr.tcp.ack_no = 1; // Todo: Extract ack number in ig_md field then use it everywhere
        // }

        // Compute IP prefixes
        if (hdr.ipv4.isValid()) {
            ig_md.src_prefix = hdr.ipv4.src_addr & 0xffffff00;
            ig_md.dst_prefix = hdr.ipv4.dst_addr & 0xffffff00;
        }

        // Determine whether we are tracking the prefix(es)/IP(s)/port(s) of this packet,
        // and if we are, what direction (data/ACK/both) are we tracking
        monitoring_status.apply(hdr, ig_md.seq_match_type, ig_md.ack_match_type);

        // Determine whether the packet should proceed for RTT computation SEQ/ACK processing
        // If it should proceed, compute expected ACK# (for SEQ)
        validation.apply(hdr, ig_md.seq_match_type, ig_md.ack_match_type,
                            ig_md.seq_validity_type, ig_md.ack_validity_type,
                            ig_md.expected_ack);
        
        // RTT processing (ingress)
        bool is_seqack_valid = (ig_md.seq_validity_type == SEQ_VALIDITY_HIT || ig_md.ack_validity_type == ACK_VALIDITY_HIT);
        bool is_recirculated = (ig_md.ingress_port == RECIRCULATION_PORT);
        if (hdr.dart_recirc.isValid() || (is_seqack_valid && is_recirculated)) {
            // Send for RTT processing
            rtt_computation_ingress.apply(hdr, ig_md.ingress_port,
                                            ig_md.seq_validity_type, ig_md.ack_validity_type,
                                            ig_md.expected_ack, ingress_timestamp,
                                            ig_md.rtt_ingress,
                                            ig_md.packet_fate);
        }
        else if (is_seqack_valid) {
            // The mirrored copy will be used to compute RTT sample
            ig_md.packet_fate = PKT_FATE_MIRROR_COMPUTE_RTT_AND_EGRESS;
        }
        else {
            // Packet doesn't quality for RTT computation, let it egress normally
            ig_md.packet_fate = PKT_FATE_BYPASS_EGRESS_AND_EGRESS;
        }

        // Passive mitigation by tracking changes in minRTT across 3 windows
        passive_mitigation.apply(hdr, is_recirculated, ig_md.src_prefix, ig_md.dst_prefix, ig_md.packet_fate);

        // // Active mitigation by crafting and sending a honeypot packet, and receiving a honeypot ACK
        // active_mitigation.apply(hdr, ig_md.ingress_port, ingress_timestamp,
        //                         ig_md.seq_validity_type, ig_md.ack_validity_type,
        //                         ig_md.expected_ack, ig_md.src_prefix, ig_md.dst_prefix, ig_md.packet_fate);

        // Set up mirroring
        egress_handoff.apply(hdr, ig_md.ingress_port, ig_md.packet_fate,
                                ig_dprsr_md.mirror_type, ig_md.mirror_session_id,
                                ig_md.handoff_type, ig_tm_md.bypass_egress);
        
        // // Drop packets from blacklisted prefixes
        // access_control.apply(hdr, ig_md.src_prefix, ig_md.dst_prefix, ig_md.packet_fate);

        // Forwarding decision based on "packet fate", packet headers, and ingress port
        basic_forwarding.apply(hdr, ig_md.ingress_port, ig_md.packet_fate,
                                ig_tm_md.ucast_egress_port, ig_dprsr_md.drop_ctl);
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    RTT_Computation_Egress()   rtt_computation_egress;
    
    // Register<bit<16>, bit<1>>(1) pctr;
    // // Counter: SEQ packets
    // RegisterAction<bit<16>, bit<1>, bool>(pctr) pctr_incr = {
    //     void apply(inout bit<16> mem_cell, out bool ret_val) {
    //         ret_val = true;
    //         mem_cell = mem_cell + 1;
    //     } };
    // action act_counter_seq_packets_increment() { pctr_incr.execute(0); }

    apply {
        
        // Extract handoff type and ingress port from bridged header
        if (hdr.bridged_md.isValid()) {
            eg_md.handoff_type = hdr.bridged_md.handoff_type;
            eg_md.ingress_port = hdr.bridged_md.ingress_port;
        }
        // Extract handoff type from mirrored header
        else if (hdr.mirror_md.isValid()) {
            eg_md.handoff_type = hdr.mirror_md.handoff_type;
        }

        // act_counter_seq_packets_increment();

        // Run egress half of RTT computation on recirculated copy
        bool is_bridged = (eg_md.handoff_type == HANDOFF_TYPE_BRIDGE || eg_md.handoff_type == HANDOFF_TYPE_BRIDGE_REPORT);
        bool is_recirculated = (eg_md.ingress_port == RECIRCULATION_PORT);
        if (hdr.dart_recirc.isValid() || (is_bridged && is_recirculated)) {
            rtt_computation_egress.apply(hdr, eg_md.rtt_egress, eg_md.packet_fate);
        }
        // Mirrored copy to be recirculated
        else if (eg_md.handoff_type == HANDOFF_TYPE_MIRROR_COMPUTE_RTT
                    || eg_md.handoff_type == HANDOFF_TYPE_MIRROR_REPORT_RTT
                    || eg_md.handoff_type == HANDOFF_TYPE_MIRROR_HONEYPOT) {
            eg_md.packet_fate = PKT_FATE_NORMAL_EGRESS;
        }
        // Any other type of packet should not reach egress
        else {
            eg_md.packet_fate = PKT_FATE_DROP;
        }

        if (eg_md.packet_fate == PKT_FATE_REPORT_EGRESS) {
            // Set up egress mirroring
            eg_dprsr_md.mirror_type = MIRROR_TYPE_E2E; // Takes values 1-7 in ingress, and 0-7 in egress
            eg_dprsr_md.mirror_io_select = 1; // E2E mirroring for Tofino2 & future ASICs
            eg_md.mirror_session_id = MIRROR_REPORT_SESSION_ID;
            eg_md.handoff_type = HANDOFF_TYPE_MIRROR_REPORT_RTT;
        }

        // // Invalidate the bridge and mirror headers
        // hdr.bridged_md.setInvalid();
        // hdr.mirror_md.setInvalid();

        if (eg_md.packet_fate == PKT_FATE_DROP) {
            eg_dprsr_md.drop_ctl = 0x1;
        } else {
            eg_dprsr_md.drop_ctl = 0x0;
        }
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
