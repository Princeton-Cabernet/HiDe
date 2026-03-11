// Parsers and Deparsers

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        // pkt.advance(PORT_METADATA_SIZE);
        // transition accept;
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_ingress_parser;

    state start {
        ig_md.src_prefix = NULL;
        ig_md.dst_prefix = NULL;
        ig_md.seq_match_type = NULL;
        ig_md.ack_match_type = NULL;
        ig_md.seq_validity_type = NULL;
        ig_md.ack_validity_type = NULL;
        ig_md.expected_ack = NULL;
        ig_md.packet_fate  = NULL;
        ig_md.mirror_session_id = NULL;
        ig_md.handoff_type = NULL;
        ig_md.ingress_port = NULL;

        // Initialize RTT computation ingress variables
        ig_md.rtt_ingress.do_flow_signatures_match = false;

        ig_md.rtt_ingress.rtt_in_type     = NULL;
        ig_md.rtt_ingress.rtt_status_type = NULL;
        ig_md.rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_NONE;
        
        ig_md.rtt_ingress.sub_result_flow_range_comparison_crcl = 1;
        ig_md.rtt_ingress.sub_result_flow_range_comparison_crrr = 1;
        ig_md.rtt_ingress.sub_result_flow_range_comparison_clrr = 1;
        ig_md.rtt_ingress.sub_result_flow_range_comparison_crrl = 1;
        ig_md.rtt_ingress.sub_result_flow_signatures = 1;
        
        ig_md.rtt_ingress.rangetracker_index  = NULL;
        // ig_md.rtt_ingress.packettracker_index = NULL;
        
        // ig_md.rtt_ingress.flow_signature   = NULL;
        // ig_md.rtt_ingress.packet_signature = NULL;

        ig_md.rtt_ingress.range_record_current.flow_signature = NULL;
        ig_md.rtt_ingress.range_record_current.flow_range.right_edge = NULL;
        ig_md.rtt_ingress.range_record_current.flow_range.left_edge  = NULL;

        ig_md.rtt_ingress.range_record_read.flow_signature = NULL;
        ig_md.rtt_ingress.range_record_read.flow_range.right_edge = NULL;
        ig_md.rtt_ingress.range_record_read.flow_range.left_edge  = NULL;

        // ig_md.rtt_ingress.packet_record_current.expected_ack = NULL;
        // ig_md.rtt_ingress.packet_record_current.timestamp    = NULL;
        // ig_md.rtt_ingress.packet_record_read.expected_ack    = NULL;
        // ig_md.rtt_ingress.packet_record_read.timestamp       = NULL;

        ig_md.rtt_ingress.left_edge_computed = NULL;

        // ig_md.rtt_ingress.rangetracker_index  = NULL;
        // ig_md.rtt_ingress.packettracker_index = NULL;

        // ig_md.rtt_ingress.flow_signature   = NULL;
        // ig_md.rtt_ingress.packet_signature = NULL;

        ig_md.rtt_ingress.recirculate_flow_record = false;

        tofino_ingress_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_DART : parse_dart_recirc;
            default : reject;
        }
    }

    state parse_dart_recirc {
        pkt.extract(hdr.dart_recirc);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_rtt;
            default : reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_rtt {
        pkt.extract(hdr.rtt_report);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Mirror() mirror;
    // Checksum() ipv4_checksum;

    apply {
        // The mirror_h header provided as the second argument to emit()
        // will become the first header on the mirrored packet.
        // The egress parser will check for that header
        if (ig_intr_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(ig_md.mirror_session_id, 
                                  {ig_md.handoff_type});
        }

        // hdr.ipv4.hdr_checksum = ipv4_checksum.update(
        //     {hdr.ipv4.version,
        //     hdr.ipv4.ihl,
        //     hdr.ipv4.dscp,
        //     hdr.ipv4.ecn,
        //     hdr.ipv4.total_len,
        //     hdr.ipv4.identification,
        //     hdr.ipv4.flags,
        //     hdr.ipv4.frag_offset,
        //     hdr.ipv4.ttl,
        //     hdr.ipv4.protocol,
        //     hdr.ipv4.src_addr,
        //     hdr.ipv4.dst_addr});

        pkt.emit(hdr);
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    TofinoEgressParser() tofino_egress_parser;

    state start {
        eg_md.handoff_type = NULL;
        eg_md.ingress_port = NULL;

        // RTT computation egress variables
        eg_md.rtt_egress.rtt_in_type      = NULL;
        eg_md.rtt_egress.rtt_status_type  = NULL;
        eg_md.rtt_egress.flow_range_verdict_type = NULL;

        eg_md.rtt_egress.counter_seq_pkts    = 0;
        eg_md.rtt_egress.counter_recirc_pkts = 0;
        eg_md.rtt_egress.counter_ack_pkts    = 0;

        eg_md.rtt_egress.ingress_tstamp = NULL;

        eg_md.rtt_egress.range_record_current.flow_signature   = NULL;
        eg_md.rtt_egress.range_record_current.flow_range.right_edge  = NULL;
        eg_md.rtt_egress.range_record_current.flow_range.left_edge   = NULL;

        eg_md.rtt_egress.packet_record_current.expected_ack = NULL;
        eg_md.rtt_egress.packet_record_current.timestamp = NULL;

        eg_md.rtt_egress.do_packet_signatures_match = false;
        eg_md.rtt_egress.do_packet_expected_acks_match = false;

        eg_md.rtt_egress.recirculate_flow_record   = false;
        eg_md.rtt_egress.recirculate_packet_record = false;

        eg_md.rtt_egress.dart_recirc_valid = false;

        eg_md.rtt_egress.packettracker_index = NULL;
        
        eg_md.rtt_egress.sub_result_flow_signatures       = 1;
        eg_md.rtt_egress.sub_result_packet_signatures     = 1;
        eg_md.rtt_egress.sub_result_packet_expected_acks  = 1;
        eg_md.rtt_egress.sub_result_eack_comparison_right = 1;
        eg_md.rtt_egress.sub_result_eack_comparison_left  = 1;
        eg_md.rtt_egress.sampled_rtt                      = 1;

        eg_md.packet_fate = PKT_FATE_DROP;
        eg_md.mirror_session_id = NULL;

        tofino_egress_parser.apply(pkt, eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        mirror_h mirror_md_tmp = pkt.lookahead<mirror_h>();
        transition select(mirror_md_tmp.handoff_type) {
            HANDOFF_TYPE_MIRROR_COMPUTE_RTT : parse_mirror_md;
            HANDOFF_TYPE_MIRROR_REPORT_RTT  : parse_mirror_md;
            HANDOFF_TYPE_MIRROR_HONEYPOT    : parse_mirror_md;
            HANDOFF_TYPE_BRIDGE             : parse_bridged_md;
            HANDOFF_TYPE_BRIDGE_REPORT      : parse_bridged_md;
            default : reject;
        }
    }

    state parse_bridged_md {
        pkt.extract(hdr.bridged_md);
        transition parse_ethernet;
    }

    state parse_mirror_md {
        pkt.extract(hdr.mirror_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_DART: parse_dart_recirc;
            default : reject;
        }
    }

    state parse_dart_recirc {
        pkt.extract(hdr.dart_recirc);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_rtt;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_rtt {
        pkt.extract(hdr.rtt_report);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    
    Mirror() mirror;
    Checksum() ipv4_checksum;
    Checksum() udp_checksum;

    apply {
        // The mirror_h header provided as the second argument to emit()
        // will become the first header on the mirrored packet.
        // The egress parser will check for that header
        if (eg_intr_md_for_dprsr.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_h>(eg_md.mirror_session_id,
                                    {eg_md.handoff_type});
        }

        if (hdr.rtt_report.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp_ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.dart_recirc);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.rtt_report);
    }
}
