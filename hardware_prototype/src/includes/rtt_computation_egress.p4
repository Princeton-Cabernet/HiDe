// Control block to compute RTT (egress half)

control RTT_Computation_Egress (
    inout header_t hdr,
    inout RTTComputationEgress_t rtt_egress,
    inout packet_fate_type_t packet_fate
) {
    // rtt_in_type_t rtt_in_type;
    // rtt_status_type_t rtt_status_type;
    // flow_range_verdict_t flow_range_verdict_type;

    // Counter16_t counter_seq_pkts;
    // Counter16_t counter_recirc_pkts;
    // Counter8_t  counter_ack_pkts;

    // Timestamp_t ingress_tstamp;

    // RangeRecord_t  range_record_current;
    // PacketRecord_t packet_record_current;

    // bool do_packet_signatures_match;
    // bool do_packet_expected_acks_match;

    // bool recirculate_flow_record;
    // bool recirculate_packet_record;

    // bool dart_recirc_valid;

    // PacketTrackerWidth_t packettracker_index;

    // TCPSeqNum_t sub_result_flow_signatures;
    // TCPSeqNum_t sub_result_packet_signatures;
    // TCPSeqNum_t sub_result_packet_expected_acks;
    // TCPSeqNum_t sub_result_eack_comparison_right;
    // TCPSeqNum_t sub_result_eack_comparison_left;
    // Timestamp_t sampled_rtt;

    action no_action() {}

    // action initialize_module_variables() {

    //     hdr.rtt_report.setInvalid();

        // rtt_in_type      = NULL;
        // rtt_status_type  = NULL;
        // flow_range_verdict_type = NULL;

        // counter_seq_pkts    = 0;
        // counter_recirc_pkts = 0;
        // counter_ack_pkts    = 0;

        // ingress_tstamp = NULL;

        // range_record_current.flow_signature   = NULL;
        // range_record_current.flow_range.right_edge  = NULL;
        // range_record_current.flow_range.left_edge   = NULL;

        // packet_record_current.expected_ack      = NULL;
        // packet_record_current.timestamp = NULL;

        // do_packet_signatures_match = false;
        // do_packet_expected_acks_match      = false;

        // recirculate_flow_record   = false;
        // recirculate_packet_record = false;

        // dart_recirc_valid = false;
        // packet_fate       = PKT_FATE_DROP;

        // packettracker_index = NULL;
        
        // sub_result_flow_signatures       = 1;
        // sub_result_packet_signatures     = 1;
        // sub_result_packet_expected_acks          = 1;
        // sub_result_eack_comparison_right = 1;
        // sub_result_eack_comparison_left  = 1;
        // sampled_rtt                      = 1;
    // }

    // Bridged metadata for egress processing
    action act_extract_bridged_metadata() {
        
        rtt_egress.ingress_tstamp = hdr.bridged_md.dart_bridge.ingress_tstamp;

        rtt_egress.rtt_in_type     = hdr.bridged_md.dart_bridge.rtt_in_type;
        rtt_egress.rtt_status_type = hdr.bridged_md.dart_bridge.rtt_status_type;
        rtt_egress.flow_range_verdict_type = hdr.bridged_md.dart_bridge.flow_range_verdict;

        rtt_egress.range_record_current.flow_signature        = hdr.bridged_md.dart_bridge.range_record_current.flow_signature;
        rtt_egress.range_record_current.flow_range.right_edge = hdr.bridged_md.dart_bridge.range_record_current.flow_range.right_edge;
        rtt_egress.range_record_current.flow_range.left_edge  = hdr.bridged_md.dart_bridge.range_record_current.flow_range.left_edge;

        rtt_egress.sub_result_flow_signatures = hdr.bridged_md.dart_bridge.sub_result_flow_signatures;
    }

    action act_set_for_recirculation() {
        hdr.ethernet.ether_type = ETHERTYPE_DART;
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        hdr.ethernet.setValid();
        hdr.dart_recirc.setValid();
        // packet_fate = PKT_FATE_NORMAL_EGRESS;
    }

    // Determine whether to recirculate
    action set_flow_recirculation_status(bool flow_recirc) {
        rtt_egress.recirculate_flow_record = flow_recirc;
    }
    action set_flow_recirculation_as_last() {
        rtt_egress.recirculate_flow_record = true;
        hdr.dart_recirc.recirc_count_flow = RANGE_TABLE_MAX_RECIRC - 1;
    }

    // Table to determine the recirculation status
    table tab_determine_flow_recirculation_status {
        const size = 5;
        key = {
            rtt_egress.rtt_status_type: exact;
            hdr.dart_recirc.recirc_count_flow: ternary;
            rtt_egress.range_record_current.flow_signature: ternary;
            rtt_egress.range_record_current.flow_range.left_edge: ternary;
            rtt_egress.sub_result_flow_signatures: ternary;
        }
        actions = {
            set_flow_recirculation_status;
            set_flow_recirculation_as_last;
        }
        const default_action = set_flow_recirculation_status(false);
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RANGE_TABLE_MAX_RECIRC, _, _, _ ) : set_flow_recirculation_status(false);
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, NULL, _, _ ) : set_flow_recirculation_status(false);
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, _, NULL, _ ) : set_flow_recirculation_status(false); // Collapsed range record
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, _, _, 0 )    : set_flow_recirculation_as_last();
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, _, _, _ )    : set_flow_recirculation_status(true);
        }
    }

    // Recirculated Packet Assignment
    action act_assign_curr_fields_to_recirc_curr_flow_sign_header() {
        hdr.dart_recirc.range_record_current.flow_signature = rtt_egress.range_record_current.flow_signature;
    }
    action act_assign_curr_fields_to_recirc_curr_flow_header() {
        act_assign_curr_fields_to_recirc_curr_flow_sign_header();
        hdr.dart_recirc.range_record_current.flow_range.right_edge = rtt_egress.range_record_current.flow_range.right_edge;
        hdr.dart_recirc.range_record_current.flow_range.left_edge  = rtt_egress.range_record_current.flow_range.left_edge;
    }
    action act_assign_fresh_curr_fields_to_recirc_curr_packet_header() {
        hdr.dart_recirc.packet_record_current.expected_ack = rtt_egress.range_record_current.flow_range.right_edge;
        hdr.dart_recirc.packet_record_current.timestamp    = rtt_egress.ingress_tstamp;
    }
    action act_assign_curr_fields_to_recirc_curr_packet_header() {
        hdr.dart_recirc.packet_record_current.expected_ack = rtt_egress.packet_record_current.expected_ack;
        hdr.dart_recirc.packet_record_current.timestamp    = rtt_egress.packet_record_current.timestamp;
    }
    action act_assign_fresh_curr_fields_to_recirc_curr_headers() {
        act_assign_curr_fields_to_recirc_curr_flow_header();
        act_assign_fresh_curr_fields_to_recirc_curr_packet_header();
    }
    action act_assign_curr_fields_to_recirc_curr_packet_only_header() {
        act_assign_curr_fields_to_recirc_curr_flow_sign_header();
        act_assign_curr_fields_to_recirc_curr_packet_header();
    }

    action act_set_initial_recirc_counts() {
        hdr.dart_recirc.recirc_count_flow   = 1;
        hdr.dart_recirc.recirc_count_packet = 0;
    }
    action act_increment_flow_recirc_count() {
        hdr.dart_recirc.recirc_count_flow = hdr.dart_recirc.recirc_count_flow + 1;
    }
    action act_increment_packet_recirc_count() {
        hdr.dart_recirc.recirc_count_packet = hdr.dart_recirc.recirc_count_packet + 1;
    }

    action act_extract_recirc_packet_headers_only_into_curr_records() {
        rtt_egress.packet_record_current.expected_ack = hdr.dart_recirc.packet_record_current.expected_ack;
        rtt_egress.packet_record_current.timestamp    = hdr.dart_recirc.packet_record_current.timestamp;
    }
    action act_extract_recirc_packet_header_into_curr_records_for_fti_pin() {
        rtt_egress.range_record_current.flow_signature = hdr.dart_recirc.range_record_current.flow_signature;
        act_extract_recirc_packet_headers_only_into_curr_records();
    }
    action act_extract_recirc_packet_header_into_curr_records_for_fte_pre() {
        rtt_egress.range_record_current.flow_signature = hdr.dart_recirc.flow_signature_first;
        act_extract_recirc_packet_headers_only_into_curr_records();
    }

    // Packet table actions
    action subtract_for_comparison_packet_table_cycle() {
        rtt_egress.sub_result_packet_signatures    = rtt_egress.range_record_current.flow_signature - hdr.dart_recirc.flow_signature_first;
        rtt_egress.sub_result_packet_expected_acks = rtt_egress.packet_record_current.expected_ack - hdr.dart_recirc.packet_eack_first;
    }
    action subtract_for_comparison_staleness_right() {
        rtt_egress.sub_result_eack_comparison_right = rtt_egress.range_record_current.flow_range.right_edge - rtt_egress.packet_record_current.expected_ack;
    }
    action subtract_for_comparison_staleness_left() {
        rtt_egress.sub_result_eack_comparison_left = rtt_egress.packet_record_current.expected_ack - rtt_egress.range_record_current.flow_range.left_edge;
    }
    // Post-subtraction checks
    bool packet_record_valid;
    action set_packet_record_validity(bool is_valid) { packet_record_valid = is_valid; }
    table tab_packet_record_validity {
        const size = 2;
        key = {
            rtt_egress.sub_result_eack_comparison_right : ternary;
            rtt_egress.sub_result_eack_comparison_left : ternary;
        }
        actions = { set_packet_record_validity; }
        const default_action = set_packet_record_validity(false);
        const entries = {
            ( TERNARY_ZERO, TERNARY_POSITIVE ) : set_packet_record_validity(true);
            ( TERNARY_POSITIVE, TERNARY_POSITIVE ) : set_packet_record_validity(true);
        }
    }

    // Set first record value(s)
    action act_assign_first_records_to_flow_recirc_header() {
        hdr.dart_recirc.flow_signature_first = rtt_egress.range_record_current.flow_signature;
    }
    action act_assign_first_records_to_packet_recirc_header() {
        hdr.dart_recirc.packet_eack_first = rtt_egress.range_record_current.flow_range.right_edge;
    }
    action act_assign_first_records_to_recirc_headers() {
        act_assign_first_records_to_flow_recirc_header();
        act_assign_first_records_to_packet_recirc_header();
    }

    // Determine packet recirculation status
    action set_packet_recirculation_status(bool pkt_recirc) { rtt_egress.recirculate_packet_record = pkt_recirc; }
    action set_packet_recirculation_as_last() {
        rtt_egress.recirculate_packet_record = true;
        hdr.dart_recirc.recirc_count_packet = PACKET_TABLE_MAX_RECIRC - 1;
    }

    // Packet recirculation
    table tab_determine_packet_recirculation_status {
        const size = 8;
        key = {
            rtt_egress.rtt_status_type: exact;
            hdr.dart_recirc.recirc_count_packet: ternary;
            rtt_egress.packet_record_current.timestamp: ternary;
            rtt_egress.sub_result_packet_signatures: ternary;
            rtt_egress.sub_result_packet_expected_acks: ternary;
        }
        actions = { set_packet_recirculation_status; set_packet_recirculation_as_last; no_action; }
        const default_action = no_action();
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC, PACKET_TABLE_MAX_RECIRC, _, _, _ ) : set_packet_recirculation_status( false );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, NULL, _, _ ) : set_packet_recirculation_status( false );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, _, 0, 0 )    : set_packet_recirculation_as_last();
            ( RTT_STATUS_FIRST_RANGE_RECIRC, _, _, _, _ )    : set_packet_recirculation_status( true );
            ( RTT_STATUS_PACKET_RECORD_VALID, PACKET_TABLE_MAX_RECIRC, _, _, _ ) : set_packet_recirculation_status( false );
            ( RTT_STATUS_PACKET_RECORD_VALID, _, NULL, _, _ ) : set_packet_recirculation_status( false );
            ( RTT_STATUS_PACKET_RECORD_VALID, _, _, 0, 0 )    : set_packet_recirculation_as_last();
            ( RTT_STATUS_PACKET_RECORD_VALID, _, _, _, _ )    : set_packet_recirculation_status( true );
        }
    }

    action ack_set_curr_packet_record() {
        rtt_egress.packet_record_current.expected_ack = rtt_egress.range_record_current.flow_range.right_edge;
        rtt_egress.packet_record_current.timestamp    = rtt_egress.ingress_tstamp;
    }

    // Set recirculated packet type
    action act_set_outgoing_rtt_in_type(rtt_in_type_t outgoing_pkt_type) {
        hdr.dart_recirc.recirc_type = outgoing_pkt_type;
    }

    table tab_set_outgoing_rtt_in_type {
        const size = 6;
        key = {
            rtt_egress.rtt_status_type: exact;
            rtt_egress.rtt_in_type: exact;
            rtt_egress.recirculate_flow_record: exact;
            rtt_egress.recirculate_packet_record: exact;
        }
        actions = { act_set_outgoing_rtt_in_type; no_action; }
        const default_action = no_action;
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RTT_IN_TYPE_FTI_PIN, true, false ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_FTE_PRE );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RTT_IN_TYPE_FTI_PIN, false, true ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_PTE_PIN );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RTT_IN_TYPE_FTE_PIN, true, false ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_FTE_PIN );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RTT_IN_TYPE_FTE_PRE, true, false ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_FTE_PRE );
            ( RTT_STATUS_FIRST_RANGE_RECIRC, RTT_IN_TYPE_FTE_PRE, false, true ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_PTE_PIN );
            ( RTT_STATUS_PACKET_RECORD_VALID, RTT_IN_TYPE_PTE_PIN, false, true ) : act_set_outgoing_rtt_in_type( RTT_IN_TYPE_PTE_PIN );
        }
    }

    action act_set_rtt_sample_packet_headers() {

        // IPv4 header
        IPv4Addr_t temp_addr      = hdr.ipv4.src_addr;
        hdr.ipv4.version          = 4w0x4;
        hdr.ipv4.ihl              = 4w0x5;
        hdr.ipv4.dscp_ecn         = rtt_egress.counter_ack_pkts + 1;
        hdr.ipv4.identification   = rtt_egress.counter_seq_pkts;
        hdr.ipv4.protocol         = IP_PROTOCOLS_UDP;
        hdr.ipv4.src_addr         = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr         = temp_addr;
        
        // RTT report (UDP) header
        hdr.rtt_report.setValid();
        hdr.rtt_report.src_port   = hdr.tcp.dst_port;
        hdr.rtt_report.dst_port   = hdr.tcp.src_port;
        hdr.rtt_report.total_length = 20; // UDP header (8 bytes) + UDP data (4 bytes * 3 = 12 bytes)
        hdr.rtt_report.checksum  = rtt_egress.counter_recirc_pkts;
        hdr.rtt_report.ack_no    = hdr.tcp.ack_no;
        hdr.rtt_report.pt_tstamp = rtt_egress.packet_record_current.timestamp;
        hdr.rtt_report.rtt       = rtt_egress.sampled_rtt;
        hdr.tcp.setInvalid();
    }

    // Packet tracker table resources

    Hash<PacketTrackerWidth_t>(HashAlgorithm_t.CRC16) hash_packettracker_index;
    action act_compute_index_packettracker_table() {
        rtt_egress.packettracker_index = (PacketTrackerWidth_t)hash_packettracker_index.get({
            rtt_egress.range_record_current.flow_signature,
            rtt_egress.packet_record_current.expected_ack
        });
        // Test case to test collision in the PT
        // packettracker_index = 0x1;
    }

    Register<FlowSignature_t, PacketTrackerWidth_t>(REGSIZE_PACKET_TRACKER) packettracker_table_packet_signature;
    Register<TCPSeqNum_t, PacketTrackerWidth_t>(REGSIZE_PACKET_TRACKER) packettracker_table_expected_ack;
    Register<Timestamp_t, PacketTrackerWidth_t>(REGSIZE_PACKET_TRACKER) packettracker_table_timestamp;

    /* PT Packet Signature Register Actions */

    // (1) PT0GetPacketSig:: PT Stage 0 Register Action: Check packet signature match
    RegisterAction<FlowSignature_t, PacketTrackerWidth_t, bool>(packettracker_table_packet_signature) get_match_packettracker_packet_signature = {
        void apply(inout FlowSignature_t mem_cell, out bool do_pkt_signs_match) {
            do_pkt_signs_match = false;
            if (mem_cell == rtt_egress.range_record_current.flow_signature) {
                do_pkt_signs_match = true;
            }
        } };
    action act_get_match_packettracker_table_packet_signature() {
        rtt_egress.do_packet_signatures_match = get_match_packettracker_packet_signature.execute(rtt_egress.packettracker_index);
    }

    // (2) PT0SetPacketSig:: PT Stage 0 Register Action: Set packet signature
    RegisterAction<FlowSignature_t, PacketTrackerWidth_t,
        FlowSignature_t>(packettracker_table_packet_signature) set_packettracker_packet_signature = {
        void apply(inout FlowSignature_t mem_cell, out FlowSignature_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_egress.range_record_current.flow_signature;
        } };
    action act_set_packettracker_table_packet_signature() {
        rtt_egress.range_record_current.flow_signature = set_packettracker_packet_signature.execute(rtt_egress.packettracker_index);
    }


    /* PT Packet expected_ack Register Actions */

    // (1) PT0Setexpected_ack:: PT Stage 0 Register Actions: Set packet expected_ack
    RegisterAction<TCPSeqNum_t, PacketTrackerWidth_t, TCPSeqNum_t>(packettracker_table_expected_ack) set_packettracker_expected_ack = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_egress.packet_record_current.expected_ack;
        } };
    action act_set_packettracker_table_expected_ack() {
        rtt_egress.packet_record_current.expected_ack = set_packettracker_expected_ack.execute(rtt_egress.packettracker_index);
    }

    // (2) PT0GetPacketexpected_ack:: PT Stage 0 Register Action: Check packet expected_ack match
    RegisterAction<TCPSeqNum_t, PacketTrackerWidth_t, bool>(packettracker_table_expected_ack) get_match_packettracker_expected_ack = {
        void apply(inout TCPSeqNum_t mem_cell, out bool do_pkt_eacks_match) {
            do_pkt_eacks_match = false;
            if (mem_cell == rtt_egress.packet_record_current.expected_ack) {
                do_pkt_eacks_match = true;
            }
        } };
    action act_get_match_packettracker_table_expected_ack() {
        rtt_egress.do_packet_expected_acks_match = get_match_packettracker_expected_ack.execute(rtt_egress.packettracker_index);
    }

    /* PT Packet Timestamp Register Actions */

    // (1) PT0SetTimestamp:: PT Stage 0 Register Actions: Set packet timestamp
    RegisterAction<Timestamp_t, PacketTrackerWidth_t, Timestamp_t>(packettracker_table_timestamp) set_packettracker_timestamp = {
        void apply(inout Timestamp_t mem_cell, out Timestamp_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_egress.packet_record_current.timestamp;
        } };
    action act_set_packettracker_table_timestamp() {
        rtt_egress.packet_record_current.timestamp = set_packettracker_timestamp.execute(rtt_egress.packettracker_index);
    }

    // (2) PT0SampleRTT:: PT Stage 0 Register Actions: Sample RTT
    RegisterAction<Timestamp_t, PacketTrackerWidth_t, Timestamp_t>(packettracker_table_timestamp) delete_packettracker_timestamp_sample_rtt = {
        void apply(inout Timestamp_t mem_cell, out Timestamp_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = NULL;
        } };
    action act_delete_packettracker_table_timestamp_sample_rtt() {
        rtt_egress.packet_record_current.timestamp = delete_packettracker_timestamp_sample_rtt.execute(rtt_egress.packettracker_index);
    }

    // Table for PT packet signature action
    table tab_execute_pt_packet_sign_action {
        const size = 4;
        key = {
            rtt_egress.rtt_status_type: exact;
        }
        actions = {
            act_get_match_packettracker_table_packet_signature;
            act_set_packettracker_table_packet_signature;
            @defaultonly no_action;
        }
        const default_action = no_action;
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED ) : act_set_packettracker_table_packet_signature();
            ( RTT_STATUS_PACKET_RECORD_VALID ) : act_set_packettracker_table_packet_signature();
            ( RTT_STATUS_SEQ_VALID_PACKET_PROCEED ) : act_set_packettracker_table_packet_signature();
            ( RTT_STATUS_ACK_VALID_PACKET_PROCEED ) : act_get_match_packettracker_table_packet_signature();
        }
    }

    // Table for PT expected_ack action
    table tab_execute_pt_packet_expected_ack_action {
        const size = 4;
        key = {
            rtt_egress.rtt_status_type: exact;
        }
        actions = { act_get_match_packettracker_table_expected_ack; act_set_packettracker_table_expected_ack; no_action; }
        const default_action = no_action;
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED ) : act_set_packettracker_table_expected_ack();
            ( RTT_STATUS_PACKET_RECORD_VALID ) : act_set_packettracker_table_expected_ack();
            ( RTT_STATUS_SEQ_VALID_PACKET_PROCEED ) : act_set_packettracker_table_expected_ack();
            ( RTT_STATUS_ACK_VALID_PACKET_PROCEED ) : act_get_match_packettracker_table_expected_ack();
        }
    }

    // Table for PT timestamp action
    table tab_execute_pt_packet_timestamp_action {
        const size = 4;
        key = {
            rtt_egress.rtt_status_type: exact;
        }
        actions = {
            act_delete_packettracker_table_timestamp_sample_rtt;
            act_set_packettracker_table_timestamp;
            @defaultonly no_action;
        }
        const default_action = no_action;
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED ) : act_set_packettracker_table_timestamp();
            ( RTT_STATUS_PACKET_RECORD_VALID ) : act_set_packettracker_table_timestamp();
            ( RTT_STATUS_SEQ_VALID_PACKET_PROCEED ) : act_set_packettracker_table_timestamp();
            ( RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH ) : act_delete_packettracker_table_timestamp_sample_rtt();
        }
    }

    Register<bit<16>, bit<1>>(1) counter_seq_packets;
    Register<bit<16>, bit<1>>(1) counter_recirc_packets;
    Register<bit<8>,  bit<1>>(1) counter_ack_packets;


    // Counter: SEQ packets
    RegisterAction<bit<16>, bit<1>, bit<16>>(counter_seq_packets) counter_seq_packets_get_and_clear = {
        void apply(inout bit<16> mem_cell, out bit<16> ret_val) {
            ret_val = mem_cell;
            mem_cell = 0;
        } };
    RegisterAction<bit<16>, bit<1>, bool>(counter_seq_packets) counter_seq_packets_increment = {
        void apply(inout bit<16> mem_cell, out bool ret_val) {
            ret_val = true;
            mem_cell = mem_cell + 1;
        } };
    action act_counter_seq_packets_increment()     { counter_seq_packets_increment.execute(0); }
    action act_counter_seq_packets_get_and_clear() { rtt_egress.counter_seq_pkts = counter_seq_packets_get_and_clear.execute(0); }


    // Counter: Recirculated packets
    RegisterAction<bit<16>, bit<1>, bit<16>>(counter_recirc_packets) counter_recirc_packets_get_and_clear = {
        void apply(inout bit<16> mem_cell, out bit<16> ret_val) {
            ret_val = mem_cell;
            mem_cell = 0;
        } };
    RegisterAction<bit<16>, bit<1>, bool>(counter_recirc_packets) counter_recirc_packets_increment = {
        void apply(inout bit<16> mem_cell, out bool ret_val) {
            ret_val = true;
            mem_cell = mem_cell + 1;
        } };
    action act_counter_recirc_packets_increment()     { counter_recirc_packets_increment.execute(0); }
    action act_counter_recirc_packets_get_and_clear() { rtt_egress.counter_recirc_pkts = counter_recirc_packets_get_and_clear.execute(0); }


    // Counter: ACK packets
    RegisterAction<bit<8>, bit<1>, bit<8>>(counter_ack_packets) counter_ack_packets_get_and_clear = {
        void apply(inout bit<8> mem_cell, out bit<8> ret_val) {
            ret_val = mem_cell;
            mem_cell = 0;
        } };
    RegisterAction<bit<8>, bit<1>, bool>(counter_ack_packets) counter_ack_packets_increment = {
        void apply(inout bit<8> mem_cell, out bool ret_val) {
            ret_val = true;
            mem_cell = mem_cell + 1;
        } };
    action act_counter_ack_packets_increment()     { counter_ack_packets_increment.execute(0); }
    action act_counter_ack_packets_get_and_clear() { rtt_egress.counter_ack_pkts = counter_ack_packets_get_and_clear.execute(0); }


    // SEQ packet counter decision
    table tab_process_counter_seq_packets {
        const size = 2;
        key = {
            rtt_egress.rtt_status_type: ternary;
            rtt_egress.rtt_in_type: ternary;
        }
        actions = { act_counter_seq_packets_increment; act_counter_seq_packets_get_and_clear; no_action; }
        const default_action = no_action();
        const entries = {
            ( RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH, _ ) : act_counter_seq_packets_get_and_clear();
            ( _,  RTT_IN_TYPE_TCP_PIN ) : act_counter_seq_packets_increment();
        }
    }

    // Recirculated packet counter decision
    table tab_process_counter_action_recirc_packets {
        const size = 2;
        key = {
            rtt_egress.rtt_status_type: ternary;
            rtt_egress.dart_recirc_valid: exact;
        }
        actions = { act_counter_recirc_packets_increment; act_counter_recirc_packets_get_and_clear; no_action; }
        const default_action = no_action();
        const entries = {
            ( RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH, false ) : act_counter_recirc_packets_get_and_clear();
            ( _,  true  ) : act_counter_recirc_packets_increment();
        }
    }

    // ACK packet counter decision
    table tab_process_counter_ack_packets {
        const size = 3;
        key = {
            rtt_egress.rtt_status_type: ternary;
            rtt_egress.rtt_in_type: ternary;
        }
        actions = { act_counter_ack_packets_increment; act_counter_ack_packets_get_and_clear; no_action; }
        const default_action = no_action();
        const entries = {
            ( RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH, _ ) : act_counter_ack_packets_get_and_clear();
            ( _, RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK ) : act_counter_ack_packets_increment();
            ( _, RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK ) : act_counter_ack_packets_increment();
        }
    }

    apply {

        // initialize_module_variables();
        act_extract_bridged_metadata();
        hdr.rtt_report.setInvalid();
        rtt_egress.dart_recirc_valid = hdr.dart_recirc.isValid();

        tab_determine_flow_recirculation_status.apply();

        bool is_seq_valid = (rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID
                            || rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_WRAPAROUND_ADJUSTED
                            || rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_FULL_OVERLAP
                            || rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_EXTENSION
                            || rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_PARTIAL_OVERLAP
                            || rtt_egress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_HOLE);

        if (rtt_egress.recirculate_flow_record) {
            act_set_for_recirculation();
            act_assign_curr_fields_to_recirc_curr_flow_header();
            act_increment_flow_recirc_count();
            rtt_egress.rtt_status_type = RTT_STATUS_RANGE_RECORD_RECIRC_SETUP;
            packet_fate = PKT_FATE_NORMAL_EGRESS;
        }

        else if (rtt_egress.rtt_status_type == RTT_STATUS_FIRST_RANGE_RECIRC
                    && rtt_egress.rtt_in_type == RTT_IN_TYPE_FTI_PIN
                    && hdr.dart_recirc.isValid()) {
            act_extract_recirc_packet_header_into_curr_records_for_fti_pin();
            rtt_egress.rtt_status_type = RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED; //52
        }
        
        else if (rtt_egress.rtt_status_type == RTT_STATUS_FIRST_RANGE_RECIRC
                    && rtt_egress.rtt_in_type == RTT_IN_TYPE_FTE_PRE
                    && hdr.dart_recirc.isValid()) {
            act_extract_recirc_packet_header_into_curr_records_for_fte_pre();
            rtt_egress.rtt_status_type = RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED; //52
        }

        else if (rtt_egress.rtt_status_type == RTT_STATUS_PACKET_RECIRC_AND_FLOW_SIGNATURES_MATCH
                    && hdr.dart_recirc.isValid()) {
            act_extract_recirc_packet_headers_only_into_curr_records();
            subtract_for_comparison_staleness_right();
            subtract_for_comparison_staleness_left();
            tab_packet_record_validity.apply();

            if (packet_record_valid) {
                rtt_egress.rtt_status_type = RTT_STATUS_PACKET_RECORD_VALID; //62
            }
        }

        else if (is_seq_valid && rtt_egress.flow_range_verdict_type == FLOW_RANGE_VERDICT_NONE) {

            act_set_for_recirculation(); // Recirculate FTI
            act_set_outgoing_rtt_in_type(RTT_IN_TYPE_FTI_PIN);
            
            // Set first records
            act_assign_first_records_to_recirc_headers();
            // Set current records
            act_assign_fresh_curr_fields_to_recirc_curr_headers();
            // Set initial recirculation counts
            act_set_initial_recirc_counts();
            rtt_egress.rtt_status_type = RTT_STATUS_FTI_PIN_RECIRC_SETUP; //78
            packet_fate = PKT_FATE_NORMAL_EGRESS;
        }
        
        else if (is_seq_valid && rtt_egress.flow_range_verdict_type == FLOW_RANGE_VERDICT_PROCEED) {
            ack_set_curr_packet_record();
            rtt_egress.rtt_status_type = RTT_STATUS_SEQ_VALID_PACKET_PROCEED; //79
        }
        
        // RTT_IN_TYPE_TCP_ACK or RTT_IN_TYPE_TCP_BTH
        else if ( (rtt_egress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK
                    || rtt_egress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK)
                    && rtt_egress.flow_range_verdict_type == FLOW_RANGE_VERDICT_PROCEED) {
            ack_set_curr_packet_record();
            rtt_egress.rtt_status_type = RTT_STATUS_ACK_VALID_PACKET_PROCEED; //85
        }
        
        // Compute PT index
        act_compute_index_packettracker_table();
        
        // PT packet signature action
        tab_execute_pt_packet_sign_action.apply();

        // PT expected_ack action
        tab_execute_pt_packet_expected_ack_action.apply();

        if (rtt_egress.rtt_status_type == RTT_STATUS_ACK_VALID_PACKET_PROCEED
                && rtt_egress.do_packet_signatures_match
                && rtt_egress.do_packet_expected_acks_match) {
            rtt_egress.rtt_status_type = RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH; //86
        }

        // PT timestamp action
        tab_execute_pt_packet_timestamp_action.apply();

        if (rtt_egress.rtt_status_type == RTT_STATUS_PACKET_RECORD_VALID) {
            // Determine whether PT record needs to recirculate
            subtract_for_comparison_packet_table_cycle();
        }

        // Determine whether PT record needs to recirculate
        tab_determine_packet_recirculation_status.apply();

        // Counter actions
        tab_process_counter_seq_packets.apply();
        tab_process_counter_action_recirc_packets.apply();
        tab_process_counter_ack_packets.apply();

        if ((rtt_egress.rtt_status_type == RTT_STATUS_FIRST_RANGE_RECIRC_EXTRACTED
                || rtt_egress.rtt_status_type == RTT_STATUS_PACKET_RECORD_VALID)
             && rtt_egress.recirculate_packet_record) {

            act_set_for_recirculation();
            act_assign_curr_fields_to_recirc_curr_packet_only_header();
            act_increment_packet_recirc_count();
            packet_fate = PKT_FATE_NORMAL_EGRESS;
        }

        else if (rtt_egress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_PACKET_SIGNATURES_MATCH
                    && hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            rtt_egress.sampled_rtt = rtt_egress.ingress_tstamp - rtt_egress.packet_record_current.timestamp;
            act_set_rtt_sample_packet_headers();
            packet_fate = PKT_FATE_REPORT_EGRESS;
        }

        if (packet_fate != PKT_FATE_NORMAL_EGRESS && packet_fate != PKT_FATE_REPORT_EGRESS) {
            packet_fate = PKT_FATE_DROP;
        }

        tab_set_outgoing_rtt_in_type.apply();
    }
}