// Control block to set up mirroring

#define MIRROR_SESSION_ID 100
#define MIRROR_REPORT_SESSION_ID 200

control Egress_Handoff (
    inout header_t hdr,
    in bit<16> ingress_port,
    inout packet_fate_type_t packet_fate,
    inout MirrorType_t mirror_type,
    inout MirrorId_t mirror_session_id,
    inout handoff_type_t handoff_type,
    inout bit<1> bypass_egress
) {
    apply {

        if (packet_fate == PKT_FATE_MIRROR_COMPUTE_RTT_AND_EGRESS) {
            mirror_type = MIRROR_TYPE_I2E;  // Takes values 1-7 in ingress, and 0-7 in egress
            mirror_session_id = MIRROR_SESSION_ID;
            handoff_type = HANDOFF_TYPE_MIRROR_COMPUTE_RTT;
            packet_fate = PKT_FATE_BYPASS_EGRESS_AND_EGRESS;
        }
        // else if (packet_fate == PKT_FATE_MIRROR_REPORT_AND_EGRESS) {
        //     mirror_type = MIRROR_TYPE_E2E;  // Takes values 1-7 in ingress, and 0-7 in egress
        //     mirror_session_id = MIRROR_REPORT_SESSION_ID;
        //     handoff_type = HANDOFF_TYPE_MIRROR_REPORT_RTT;
        //     packet_fate = PKT_FATE_BYPASS_EGRESS_AND_REPORT_EGRESS;
        // }
        else if (packet_fate == PKT_FATE_MIRROR_HONEYPOT_AND_EGRESS) {
            mirror_type = MIRROR_TYPE_I2E;  // Takes values 1-7 in ingress, and 0-7 in egress
            mirror_session_id = MIRROR_SESSION_ID;
            handoff_type = HANDOFF_TYPE_MIRROR_HONEYPOT;
            packet_fate = PKT_FATE_BYPASS_EGRESS_AND_EGRESS;
        }
        
        if (hdr.rtt_report.isValid() && packet_fate == PKT_FATE_BYPASS_EGRESS_AND_EGRESS) {
            // No bridging
            bypass_egress = 0x1;
            packet_fate = PKT_FATE_DROP;
        }
        else if (packet_fate == PKT_FATE_BYPASS_EGRESS_AND_EGRESS) {
            // No bridging
            bypass_egress = 0x1;
            packet_fate = PKT_FATE_NORMAL_EGRESS;
        }
        else if (packet_fate == PKT_FATE_REPORT_EGRESS) {
            handoff_type = HANDOFF_TYPE_BRIDGE_REPORT;
            hdr.bridged_md.setValid();
            hdr.bridged_md.handoff_type = HANDOFF_TYPE_BRIDGE_REPORT;
            hdr.bridged_md.ingress_port = ingress_port;
            packet_fate = PKT_FATE_REPORT_EGRESS;
        }
        else if (packet_fate != PKT_FATE_DROP) {
            handoff_type = HANDOFF_TYPE_BRIDGE;
            hdr.bridged_md.setValid();
            hdr.bridged_md.handoff_type = HANDOFF_TYPE_BRIDGE;
            hdr.bridged_md.ingress_port = ingress_port;
            if (packet_fate != PKT_FATE_RECIRCULATE) {
                packet_fate = PKT_FATE_NORMAL_EGRESS;
            }
        }
    }
}