// Control block to determine egress port based on the IP and MAC headers

control Basic_Forwarding (
    in header_t hdr,
    in bit<16> ingress_port,
    in packet_fate_type_t packet_fate,
    inout PortId_t ucast_egress_port,
    inout bit<3> drop_ctl
) {
    action set_egress_port(PortId_t egress_port) {
        ucast_egress_port = egress_port;
    }

    table tab_ip_mac_forwarding {
        size = TABSIZE_IP_MAC_FORWARDING;
        key = {
            ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
        }
        actions = { set_egress_port; }
        const default_action = set_egress_port(DEFAULT_EGRESS_PORT);
        const entries = {
            (_, 0x0 &&& 0x0, 0x0 &&& 0x0): set_egress_port(DEFAULT_EGRESS_PORT);
        }
    }

    table tab_mac_forwarding {
        size = TABSIZE_MAC_FORWARDING;
        key = {
            ingress_port: ternary;
            hdr.ethernet.dst_addr: ternary;
        }
        actions = { set_egress_port; }
        const default_action = set_egress_port(DEFAULT_EGRESS_PORT);
        const entries = {
            (_, 0x0 &&& 0x0): set_egress_port(DEFAULT_EGRESS_PORT);
        }
    }

    apply {

        if (packet_fate == PKT_FATE_REPORT_EGRESS) {
            set_egress_port(RTT_REPORT_PORT);
        
        } else if (packet_fate == PKT_FATE_NORMAL_EGRESS && hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            // Decide egress port based on destination IP and MAC addresses
            tab_ip_mac_forwarding.apply();

        } else if (packet_fate == PKT_FATE_NORMAL_EGRESS && hdr.ethernet.isValid()) {
            // Decide egress port based on destination MAC address only
            tab_mac_forwarding.apply();

        } else if (packet_fate == PKT_FATE_RECIRCULATE) {
            set_egress_port(RECIRCULATION_PORT);
        }
    }
}