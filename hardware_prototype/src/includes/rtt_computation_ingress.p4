// Control block to compute RTT (ingress half)

const Seed4_t SEED_RANGETRACKER_INDEX = 7;
const Seed4_t SEED_FLOW_SIGNATURE = 5;

const Counter8_t RANGE_TABLE_MAX_RECIRC  = 3;
const Counter8_t PACKET_TABLE_MAX_RECIRC = 3;

control RTT_Computation_Ingress (
    inout header_t hdr,
    in bit<16> ingress_port,
    in seq_validity_type_t seq_validity_type,
    in ack_validity_type_t ack_validity_type,
    in TCPSeqNum_t expected_ack,
    in Timestamp_t ingress_timestamp,
    inout RTTComputationIngress_t rtt_ingress,
    inout packet_fate_type_t packet_fate
) {
    // bool do_flow_signatures_match;

    // rtt_in_type_t rtt_in_type;
    // rtt_status_type_t rtt_status_type;
    // flow_range_verdict_t flow_range_verdict_type;

    // RangeRecord_t range_record_current;
    // RangeRecord_t range_record_read;

    // PacketRecord_t packet_record_current;
    // PacketRecord_t packet_record_read;
    // TCPSeqNum_t    left_edge_computed;

    // TCPSeqNum_t sub_result_flow_range_comparison_crcl;
    // TCPSeqNum_t sub_result_flow_range_comparison_crrr;
    // TCPSeqNum_t sub_result_flow_range_comparison_clrr;
    // TCPSeqNum_t sub_result_flow_range_comparison_crrl;
    // TCPSeqNum_t sub_result_flow_signatures;

    // RangeTrackerWidth_t rangetracker_index;
    // PacketTrackerWidth_t packettracker_index;

    // FlowSignature_t   flow_signature;
    // PacketSignature_t packet_signature;

    // bool recirculate_flow_record;

    action no_action() {}

    // action initialize_module_variables() {
    //     do_flow_signatures_match = false;

    //     rtt_in_type     = NULL;
    //     rtt_status_type = NULL;
    //     flow_range_verdict_type = FLOW_RANGE_VERDICT_NONE;
        
    //     sub_result_flow_range_comparison_crcl = 1;
    //     sub_result_flow_range_comparison_crrr = 1;
    //     sub_result_flow_range_comparison_clrr = 1;
    //     sub_result_flow_range_comparison_crrl = 1;
    //     sub_result_flow_signatures = 1;
        
    //     rangetracker_index  = NULL;
    //     packettracker_index = NULL;
        
    //     flow_signature   = NULL;
    //     packet_signature = NULL;

    //     range_record_current.flow_signature = NULL;
    //     range_record_current.flow_range.right_edge = NULL;
    //     range_record_current.flow_range.left_edge  = NULL;

    //     range_record_read.flow_signature = NULL;
    //     range_record_read.flow_range.right_edge = NULL;
    //     range_record_read.flow_range.left_edge  = NULL;

    //     packet_record_current.expected_ack = NULL;
    //     packet_record_current.timestamp    = NULL;
    //     packet_record_read.expected_ack    = NULL;
    //     packet_record_read.timestamp       = NULL;

    //     left_edge_computed = NULL;

    //     rangetracker_index  = NULL;
    //     packettracker_index = NULL;

    //     flow_signature   = NULL;
    //     packet_signature = NULL;

    //     recirculate_flow_record = false;
    // }

    Hash<FlowSignature_t>(HashAlgorithm_t.CRC32,
            CRCPolynomial<FlowSignature_t>(CRC_POLY_3,false,false,false,0,0)) hash_flow_seq_signature;
    Hash<FlowSignature_t>(HashAlgorithm_t.CRC32,
            CRCPolynomial<FlowSignature_t>(CRC_POLY_3,false,false,false,0,0)) hash_flow_ack_signature;
    action compute_flow_seq_signature() {
        rtt_ingress.range_record_current.flow_signature = hash_flow_seq_signature.get({
            SEED_FLOW_SIGNATURE,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.tcp.src_port,
            hdr.tcp.dst_port
        });
    }
    action compute_flow_ack_signature() {
        rtt_ingress.range_record_current.flow_signature = hash_flow_ack_signature.get({
            SEED_FLOW_SIGNATURE,
            hdr.ipv4.dst_addr,
            hdr.ipv4.src_addr,
            hdr.tcp.dst_port,
            hdr.tcp.src_port
        });
    }

    // Compute flow range edges
    action compute_flow_range_seq_edges() {
        rtt_ingress.range_record_current.flow_range.right_edge = expected_ack;
        rtt_ingress.range_record_current.flow_range.left_edge  = hdr.tcp.seq_no;
    }
    action compute_flow_range_ack_rightedge() {
        rtt_ingress.range_record_current.flow_range.right_edge = hdr.tcp.ack_no;
        rtt_ingress.range_record_current.flow_range.left_edge  = hdr.tcp.ack_no;
    }

    Hash<RangeTrackerWidth_t>(HashAlgorithm_t.CRC16,
            CRCPolynomial<RangeTrackerWidth_t>(CRC_POLY_0,false,false,false,0,0)) hash_rangetracker_index;
    action compute_rangetracker_index() {
        rtt_ingress.rangetracker_index = (RangeTrackerWidth_t)hash_rangetracker_index.get({
            SEED_RANGETRACKER_INDEX,
            rtt_ingress.range_record_current.flow_signature
        });
        // Test case to test collision in the FT
        // rtt_ingress.rangetracker_index = 0x1;
    }
    // Hash<RangeTrackerWidth_t>(HashAlgorithm_t.CRC16,
    //         CRCPolynomial<RangeTrackerWidth_t>(CRC_POLY_0,false,false,false,0,0)) hash_rangetracker_seq_index;
    // action compute_rangetracker_seq_index() {
    //     rtt_ingress.rangetracker_index = (RangeTrackerWidth_t)hash_rangetracker_seq_index.get({
    //         SEED_RANGETRACKER_INDEX,
    //         hdr.ipv4.src_addr,
    //         hdr.ipv4.dst_addr,
    //         hdr.tcp.src_port,
    //         hdr.tcp.dst_port
    //     });
    //     // Test case to test collision in the FT
    //     // rtt_ingress.rangetracker_index = 0x1;
    // }
    // Hash<RangeTrackerWidth_t>(HashAlgorithm_t.CRC16,
    //         CRCPolynomial<RangeTrackerWidth_t>(CRC_POLY_0,false,false,false,0,0)) hash_rangetracker_ack_index;
    // action compute_rangetracker_ack_index() {
    //     rtt_ingress.rangetracker_index = (RangeTrackerWidth_t)hash_rangetracker_ack_index.get({
    //         SEED_RANGETRACKER_INDEX,
    //         hdr.ipv4.dst_addr,
    //         hdr.ipv4.src_addr,
    //         hdr.tcp.dst_port,
    //         hdr.tcp.src_port
    //     });
    //     // Test case to test collision in the FT
    //     // rtt_ingress.rangetracker_index = 0x1;
    // }

    // Range tracker table registers
    Register<FlowSignature_t, RangeTrackerWidth_t>(REGSIZE_RANGE_TRACKER) reg_rangetracker_flow_signature;
    Register<TCPSeqNum_t, RangeTrackerWidth_t>(REGSIZE_RANGE_TRACKER) reg_rangetracker_flowrange_rightedge;
    Register<TCPSeqNum_t, RangeTrackerWidth_t>(REGSIZE_RANGE_TRACKER) reg_rangetracker_flowrange_leftedge;

    // Check flow signature match
    RegisterAction<FlowSignature_t, RangeTrackerWidth_t, FlowSignature_t>(reg_rangetracker_flow_signature) match_rangetracker_flow_signature = {
        void apply(inout FlowSignature_t mem_cell, out FlowSignature_t sub_match) {
            sub_match = mem_cell - rtt_ingress.range_record_current.flow_signature;
            // is_match = false;
            // if (mem_cell == rtt_ingress.range_record_current.flow_signature) {
            //     is_match = true;
            // }
            // else {
            //     do_flow_signatures_match = false;
            // }
        } };
    FlowSignature_t sub_flow_signatures_match;
    action act_match_rangetracker_flow_signature() {
        // rtt_ingress.do_flow_signatures_match = match_rangetracker_flow_signature.execute(rtt_ingress.rangetracker_index);
        sub_flow_signatures_match = match_rangetracker_flow_signature.execute(rtt_ingress.rangetracker_index);
    }

    // Set flow signature
    RegisterAction<FlowSignature_t, RangeTrackerWidth_t, FlowSignature_t>(reg_rangetracker_flow_signature) set_rangetracker_flow_signature = {
        void apply(inout FlowSignature_t mem_cell, out FlowSignature_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_ingress.range_record_current.flow_signature;
        } };
    action act_set_rangetracker_flow_signature() {
        rtt_ingress.range_record_current.flow_signature = set_rangetracker_flow_signature.execute(rtt_ingress.rangetracker_index);
    }

    // Get flow range right edge
    RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) get_rangetracker_flowrange_rightedge = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val  = mem_cell;
        } };
    action act_get_rangetracker_flowrange_rightedge_seq() {
        rtt_ingress.range_record_current.flow_range.right_edge = get_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    }
    action act_get_rangetracker_flowrange_rightedge_ack() {
        rtt_ingress.range_record_read.flow_range.right_edge = get_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    }

    // Set flow range right edge
    RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) set_rangetracker_flowrange_rightedge = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_ingress.range_record_current.flow_range.right_edge;
        } };
    action act_set_rangetracker_flowrange_rightedge() {
        rtt_ingress.range_record_current.flow_range.right_edge = set_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    }

    // Update flow range right edge for SEQ direction: Set to value if value is greater than existing value
    RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) setmax_rangetracker_flowrange_rightedge = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val = mem_cell;
            if (mem_cell < rtt_ingress.range_record_current.flow_range.right_edge) {
                mem_cell = rtt_ingress.range_record_current.flow_range.right_edge;
            }
        } };
    action act_setmax_rangetracker_flowrange_rightedge() {
        rtt_ingress.range_record_read.flow_range.right_edge = setmax_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    }

    action set_rtt_in_packet_type(rtt_in_type_t _rtt_in_type) {
        rtt_ingress.rtt_in_type = _rtt_in_type;
    }

    // Extract recirculated packet headers
    action extract_recirc_range_header_into_current_records() {
        rtt_ingress.range_record_current.flow_signature        = hdr.dart_recirc.range_record_current.flow_signature;
        rtt_ingress.range_record_current.flow_range.right_edge = hdr.dart_recirc.range_record_current.flow_range.right_edge;
        rtt_ingress.range_record_current.flow_range.left_edge  = hdr.dart_recirc.range_record_current.flow_range.left_edge;
        // Default computed left edge is the extracted left edge
        rtt_ingress.left_edge_computed = hdr.dart_recirc.range_record_current.flow_range.left_edge;
    }
    action extract_recirc_packet_header_into_current_records() {
        rtt_ingress.range_record_current.flow_signature = hdr.dart_recirc.range_record_current.flow_signature;
    }


    // Range tracker table: Flow signature action
    table tab_execute_rangetracker_flow_signature_action {
        const size = 4;
        key = {
            rtt_ingress.rtt_status_type: exact;
        }
        actions = { act_match_rangetracker_flow_signature; act_set_rangetracker_flow_signature; no_action; }
        const default_action = no_action;
        const entries = {
            ( RTT_STATUS_FIRST_RANGE_RECIRC ) : act_set_rangetracker_flow_signature();
            ( RTT_STATUS_PACKET_RECIRC ) : act_match_rangetracker_flow_signature();
            ( RTT_STATUS_SEQ_VALID ) : act_match_rangetracker_flow_signature();
            ( RTT_STATUS_ACK_VALID ) : act_match_rangetracker_flow_signature();
        }
    }

    // Range tracker table: Flow range right edge register
    // Register<TCPSeqNum_t, RangeTrackerWidth_t>(REGSIZE_RANGE_TRACKER) reg_rangetracker_flowrange_rightedge;
    // RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) get_rangetracker_flowrange_rightedge = {
    //     void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
    //         ret_val  = mem_cell;
    //     } };
    // RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) set_rangetracker_flowrange_rightedge = {
    //     void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
    //         ret_val  = mem_cell;
    //         mem_cell = rtt_ingress.range_record_current.flow_range.right_edge;
    //     } };
    // RegisterAction<TCPSeqNum_t, RangeTrackerWidth_t, TCPSeqNum_t>(reg_rangetracker_flowrange_rightedge) setmax_rangetracker_flowrange_rightedge = {
    // void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
    //     ret_val = mem_cell;
    //     if (mem_cell < rtt_ingress.range_record_current.flow_range.right_edge) {
    //         mem_cell = rtt_ingress.range_record_current.flow_range.right_edge;
    //     }
    // } };
    // action act_get_rangetracker_flowrange_rightedge_seq() {
    //     rtt_ingress.range_record_current.flow_range.right_edge = get_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    // }
    // action act_get_rangetracker_flowrange_rightedge_ack() {
    //     rtt_ingress.range_record_read.flow_range.right_edge = get_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    // }
    // action act_set_rangetracker_flowrange_rightedge() {
    //     rtt_ingress.range_record_current.flow_range.right_edge = set_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    // }
    // action act_setmax_rangetracker_flowrange_rightedge() {
    //     rtt_ingress.range_record_read.flow_range.right_edge = setmax_rangetracker_flowrange_rightedge.execute(rtt_ingress.rangetracker_index);
    // }

    // Table to read/write the range tracker flow range right edge
    table tab_execute_rangetracker_flowrange_rightedge_action {
        const size = 5;
        key = {
            rtt_ingress.rtt_status_type: exact;
        }
        actions = {
            act_get_rangetracker_flowrange_rightedge_seq;
            act_get_rangetracker_flowrange_rightedge_ack;
            act_set_rangetracker_flowrange_rightedge;
            act_setmax_rangetracker_flowrange_rightedge;
            no_action;
        }
        const default_action = no_action;
        const entries = {
            RTT_STATUS_FIRST_RANGE_RECIRC: act_set_rangetracker_flowrange_rightedge();
            RTT_STATUS_PACKET_RECIRC_AND_FLOW_SIGNATURES_MATCH: act_get_rangetracker_flowrange_rightedge_seq();
            RTT_STATUS_SEQ_VALID_AND_WRAPPED_AROUND: act_set_rangetracker_flowrange_rightedge();
            RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND: act_setmax_rangetracker_flowrange_rightedge();
            RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH: act_get_rangetracker_flowrange_rightedge_ack();
        }
    }

    // Range tracker table: Flow range left edge register
    // Register<TCPSeqNum_t, bit<16>>(REGSIZE_RANGE_TRACKER) reg_rangetracker_flowrange_leftedge;
    RegisterAction<TCPSeqNum_t, bit<16>, TCPSeqNum_t>(reg_rangetracker_flowrange_leftedge) get_rangetracker_flowrange_leftedge = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val = mem_cell;
        } };
    RegisterAction<TCPSeqNum_t, bit<16>, TCPSeqNum_t>(reg_rangetracker_flowrange_leftedge) set_rangetracker_flowrange_leftedge = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = rtt_ingress.left_edge_computed;
        } };
    RegisterAction<TCPSeqNum_t, bit<16>, TCPSeqNum_t>(reg_rangetracker_flowrange_leftedge) update_rangetracker_flowrange_leftedge_setinifnull = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val = mem_cell;
            if (mem_cell == NULL) {
                mem_cell = rtt_ingress.left_edge_computed;
            }
        } };
    RegisterAction<TCPSeqNum_t, bit<16>, TCPSeqNum_t>(reg_rangetracker_flowrange_leftedge) update_rangetracker_flowrange_leftedge_setnewifmaxornullifequal = {
        void apply(inout TCPSeqNum_t mem_cell, out TCPSeqNum_t ret_val) {
            ret_val = mem_cell;
            if (rtt_ingress.range_record_current.flow_range.right_edge > mem_cell) {
                mem_cell = rtt_ingress.range_record_current.flow_range.right_edge;
            } else if (rtt_ingress.range_record_current.flow_range.right_edge == mem_cell) {
                mem_cell = NULL;
            }
        } };
    action act_get_rangetracker_flowrange_leftedge() {
        rtt_ingress.range_record_current.flow_range.left_edge = get_rangetracker_flowrange_leftedge.execute(rtt_ingress.rangetracker_index);
    }
    action act_set_rangetracker_flowrange_leftedge() {
        rtt_ingress.range_record_current.flow_range.left_edge = set_rangetracker_flowrange_leftedge.execute(rtt_ingress.rangetracker_index);
    }
    // action act_update_rangetracker_flowrange_leftedge_setnull() {
    //     rtt_ingress.left_edge_computed = NULL;
    //     act_set_rangetracker_flowrange_leftedge();
    // }
    action act_update_rangetracker_flowrange_leftedge_setinifnull() {
        update_rangetracker_flowrange_leftedge_setinifnull.execute(rtt_ingress.rangetracker_index);
    }
    action act_update_rangetracker_flowrange_leftedge_setnewifmaxornullifequal() {
        rtt_ingress.range_record_read.flow_range.left_edge = update_rangetracker_flowrange_leftedge_setnewifmaxornullifequal.execute(rtt_ingress.rangetracker_index);
    }

    // Table to read/write the range tracker flow range left edge
    table tab_execute_rangetracker_flowrange_leftedge_action {
        const size = 9;
        key = {
            rtt_ingress.rtt_status_type: exact;
        }
        actions = {
            act_get_rangetracker_flowrange_leftedge;
            act_set_rangetracker_flowrange_leftedge;
            // act_update_rangetracker_flowrange_leftedge_setnull;
            act_update_rangetracker_flowrange_leftedge_setinifnull;
            act_update_rangetracker_flowrange_leftedge_setnewifmaxornullifequal;
            no_action;
        }
        const default_action = no_action;
        const entries = {
            RTT_STATUS_FIRST_RANGE_RECIRC:
                act_set_rangetracker_flowrange_leftedge();
            RTT_STATUS_PACKET_RECIRC_AND_FLOW_SIGNATURES_MATCH:
                act_get_rangetracker_flowrange_leftedge();
            RTT_STATUS_SEQ_VALID_AND_WRAPAROUND_ADJUSTED:
                act_set_rangetracker_flowrange_leftedge();
            // RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_FULL_OVERLAP:
            //     act_update_rangetracker_flowrange_leftedge_setnull();
            RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_FULL_OVERLAP:
                act_set_rangetracker_flowrange_leftedge();
            RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_EXTENSION:
                act_update_rangetracker_flowrange_leftedge_setinifnull();
            // RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_PARTIAL_OVERLAP:
            //     act_update_rangetracker_flowrange_leftedge_setnull();
            RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_PARTIAL_OVERLAP:
                act_set_rangetracker_flowrange_leftedge();
            RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_HOLE:
                act_set_rangetracker_flowrange_leftedge();
            // RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK:
            //     act_update_rangetracker_flowrange_leftedge_setnull();
            RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK:
                act_set_rangetracker_flowrange_leftedge();
            RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK:
                act_update_rangetracker_flowrange_leftedge_setnewifmaxornullifequal();
        }
    }

    /** Subtraction for comparison operations and sign-bit checks **/
    // Subtract left edge from right edge
    bool sub_crcl_negative;
    bool sub_crcl_zero;
    action subtract_for_comparison_current_edges() {
        rtt_ingress.sub_result_flow_range_comparison_crcl = rtt_ingress.range_record_current.flow_range.right_edge - rtt_ingress.range_record_current.flow_range.left_edge;
    }
    action set_crcl_negative() { sub_crcl_negative = true;  sub_crcl_zero = false; }
    action set_crcl_zero()     { sub_crcl_negative = false; sub_crcl_zero = true;  }
    action set_crcl_positive() { sub_crcl_negative = false; sub_crcl_zero = false; }
    table tab_comparison_current_edges {
        const size = 2;
        key = { rtt_ingress.sub_result_flow_range_comparison_crcl : ternary; }
        actions = { set_crcl_negative; set_crcl_zero; @defaultonly set_crcl_positive; }
        const default_action = set_crcl_positive;
        const entries = {
            TERNARY_NEGATIVE : set_crcl_negative();
            TERNARY_ZERO     : set_crcl_zero();
        }
    }

    // Subtract read right edge from current right edge
    bool sub_crrr_negative;
    bool sub_crrr_zero;
    action subtract_for_comparison_rightedges() {
        rtt_ingress.sub_result_flow_range_comparison_crrr = rtt_ingress.range_record_current.flow_range.right_edge - rtt_ingress.range_record_read.flow_range.right_edge;
    }
    action set_crrr_negative() { sub_crrr_negative = true;  sub_crrr_zero = false; }
    action set_crrr_zero()     { sub_crrr_negative = false; sub_crrr_zero = true;  }
    action set_crrr_positive() { sub_crrr_negative = false; sub_crrr_zero = false; }
    table tab_comparison_rightedges {
        const size = 2;
        key = { rtt_ingress.sub_result_flow_range_comparison_crrr : ternary; }
        actions = { set_crrr_negative; set_crrr_zero; @defaultonly set_crrr_positive; }
        const default_action = set_crrr_positive;
        const entries = {
            TERNARY_NEGATIVE : set_crrr_negative();
            TERNARY_ZERO     : set_crrr_zero();
        }
    }

    // Subtract read right edge from current left edge
    bool sub_clrr_negative;
    bool sub_clrr_zero;
    action subtract_for_comparison_curr_leftedge_with_mem_rightedge() {
        rtt_ingress.sub_result_flow_range_comparison_clrr = rtt_ingress.range_record_current.flow_range.left_edge - rtt_ingress.range_record_read.flow_range.right_edge;
    }
    action set_clrr_negative() { sub_clrr_negative = true;  sub_clrr_zero = false; }
    action set_clrr_zero()     { sub_clrr_negative = false; sub_clrr_zero = true;  }
    action set_clrr_positive() { sub_clrr_negative = false; sub_clrr_zero = false; }
    table tab_comparison_curr_leftedge_with_mem_rightedge {
        const size = 2;
        key = { rtt_ingress.sub_result_flow_range_comparison_clrr : ternary; }
        actions = { set_clrr_negative; set_clrr_zero; @defaultonly set_clrr_positive; }
        const default_action = set_clrr_positive;
        const entries = {
            TERNARY_NEGATIVE : set_clrr_negative();
            TERNARY_ZERO     : set_clrr_zero();
        }
    }

    // Subtract read left edge from current right edge
    bool sub_crrl_positive;
    bool sub_crrl_zero;
    bool sub_crrl_negative;
    action subtract_for_comparison_curr_rightedge_with_mem_leftedge() {
        rtt_ingress.sub_result_flow_range_comparison_crrl = rtt_ingress.range_record_current.flow_range.right_edge - rtt_ingress.range_record_read.flow_range.left_edge;
    }
    action set_crrl_positive() { sub_crrl_positive = true; sub_crrl_zero = false; sub_crrl_negative = false; }
    action set_crrl_zero()     { sub_crrl_positive = false; sub_crrl_zero = true; sub_crrl_negative = false; }
    action set_crrl_negative() { sub_crrl_positive = false; sub_crrl_zero = false; sub_crrl_negative = true; }
    table tab_comparison_curr_rightedge_with_mem_leftedge {
        const size = 2;
        key = { rtt_ingress.sub_result_flow_range_comparison_crrl : ternary; }
        actions = { set_crrl_positive; set_crrl_zero; @defaultonly set_crrl_negative; }
        const default_action = set_crrl_negative;
        const entries = {
            TERNARY_POSITIVE : set_crrl_positive();
            TERNARY_ZERO     : set_crrl_zero();
        }
    }

    // Subtract to match range record flow signatures
    action subtract_for_comparison_rangetracker_cycle() {
        rtt_ingress.sub_result_flow_signatures = rtt_ingress.range_record_current.flow_signature - hdr.dart_recirc.flow_signature_first;
    }

    // Bridged metadata for egress processing
    action act_populate_bridged_metadata() {

        hdr.bridged_md.dart_bridge.ingress_tstamp     = ingress_timestamp;
        hdr.bridged_md.dart_bridge.rtt_in_type        = rtt_ingress.rtt_in_type;
        hdr.bridged_md.dart_bridge.rtt_status_type    = rtt_ingress.rtt_status_type;
        hdr.bridged_md.dart_bridge.flow_range_verdict = rtt_ingress.flow_range_verdict_type;

        hdr.bridged_md.dart_bridge.range_record_current.flow_signature = rtt_ingress.range_record_current.flow_signature;
        hdr.bridged_md.dart_bridge.range_record_current.flow_range.right_edge = rtt_ingress.range_record_current.flow_range.right_edge;
        hdr.bridged_md.dart_bridge.range_record_current.flow_range.left_edge  = rtt_ingress.range_record_current.flow_range.left_edge;
        
        hdr.bridged_md.dart_bridge.sub_result_flow_signatures = rtt_ingress.sub_result_flow_signatures;
    }

    apply {

        // initialize_module_variables();

        if (hdr.dart_recirc.isValid()) {
            set_rtt_in_packet_type(hdr.dart_recirc.recirc_type);

        } else if ((seq_validity_type == SEQ_VALIDITY_HIT) && (ingress_port == RECIRCULATION_PORT)) {
            // Recirculated SEQ packet handling (ACK direction already processed)
            // set_rtt_in_packet_type(RTT_IN_TYPE_FTS_PIN);
            set_rtt_in_packet_type(RTT_IN_TYPE_TCP_PIN);
        
        } else if ((seq_validity_type == SEQ_VALIDITY_HIT) && (ack_validity_type == ACK_VALIDITY_HIT)) {
            // Fresh TCP packet handling
            set_rtt_in_packet_type(RTT_IN_TYPE_TCP_PIN);
            packet_fate = PKT_FATE_MIRROR_RTTACK_AND_EGRESS;
        
        } else if ((seq_validity_type == SEQ_VALIDITY_HIT) || (ack_validity_type == ACK_VALIDITY_HIT)) {
            // Fresh TCP packet handling
            set_rtt_in_packet_type(RTT_IN_TYPE_TCP_PIN);
        
        } else {
            set_rtt_in_packet_type(RTT_IN_TYPE_NONE);
        }

        if ((rtt_ingress.rtt_in_type == RTT_IN_TYPE_FTI_PIN)
                || (rtt_ingress.rtt_in_type == RTT_IN_TYPE_FTE_PIN)
                || (rtt_ingress.rtt_in_type == RTT_IN_TYPE_FTE_PRE)) {
            // First range record recirculation
            extract_recirc_range_header_into_current_records();
            rtt_ingress.rtt_status_type = RTT_STATUS_FIRST_RANGE_RECIRC; //50
        
        } else if (rtt_ingress.rtt_in_type == RTT_IN_TYPE_PTE_PIN) {
            // Packet record recirculation: Check range record for staleness, then insert
            extract_recirc_packet_header_into_current_records();
            rtt_ingress.rtt_status_type = RTT_STATUS_PACKET_RECIRC;
        }

        if ((seq_validity_type == SEQ_VALIDITY_HIT) && (ack_validity_type == ACK_VALIDITY_MISS)) {
            // Only SEQ direction valid
            compute_flow_seq_signature();
            // compute_rangetracker_seq_index();
            compute_flow_range_seq_edges();
            subtract_for_comparison_current_edges();
            tab_comparison_current_edges.apply();
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID;

        } else if (ack_validity_type == ACK_VALIDITY_HIT) {
            // Only ACK direction valid or both SEQ+ACK directions valid
            compute_flow_ack_signature();
            // compute_rangetracker_ack_index();
            compute_flow_range_ack_rightedge();
            rtt_ingress.rtt_status_type = RTT_STATUS_ACK_VALID;
        }

        // // Ensure the computed flow signature is non-zero since zero will confuse the registers
        // bool seq_or_ack_hit = (seq_validity_type == SEQ_VALIDITY_HIT) || (ack_validity_type == ACK_VALIDITY_HIT);
        // if (seq_or_ack_hit && rtt_ingress.range_record_current.flow_signature == 0x0) {
        //     rtt_ingress.range_record_current.flow_signature = 0x1;
        // }

        compute_rangetracker_index();
        tab_execute_rangetracker_flow_signature_action.apply();
        if (sub_flow_signatures_match == 0) {
            rtt_ingress.do_flow_signatures_match = true;
        } else {
            rtt_ingress.do_flow_signatures_match = false;
        }

        // Decide range tracker register action based on the RTT_STATUS
        // if (rtt_ingress.rtt_status_type == RTT_STATUS_FIRST_RANGE_RECIRC) {
        //     act_set_rangetracker_flow_signature();

        // } else if (rtt_ingress.rtt_status_type == RTT_STATUS_PACKET_RECIRC
        //         || rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID
        //         || rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID) {
        //     act_match_rangetracker_flow_signature();
        // }

        // Only relevant for RTT_STATUS_SEQ_VALID
        // subtract_for_comparison_current_edges();

        // Check whether flow signature matches for the first range tracker recirculation
        if (rtt_ingress.rtt_status_type == RTT_STATUS_FIRST_RANGE_RECIRC
                && (rtt_ingress.rtt_in_type == RTT_IN_TYPE_FTE_PIN
                    || rtt_ingress.rtt_in_type == RTT_IN_TYPE_FTE_PRE)) {
            subtract_for_comparison_rangetracker_cycle();
        }
        
        // Check whether flow signature matches for PTE_PIN
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_PACKET_RECIRC
                    && rtt_ingress.do_flow_signatures_match) {
            rtt_ingress.rtt_status_type = RTT_STATUS_PACKET_RECIRC_AND_FLOW_SIGNATURES_MATCH;
        }

        // Check whether flow signature matches for SEQ_VALID and whether there is a wraparound
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID
                    && rtt_ingress.do_flow_signatures_match
                    && sub_crcl_negative
                    && rtt_ingress.range_record_current.flow_range.right_edge == NULL) {
            // Lesser than (sign bit 1): Sequence number wraparound detected
            rtt_ingress.range_record_current.flow_range.right_edge = 1;
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_WRAPPED_AROUND;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID
                    && rtt_ingress.do_flow_signatures_match
                    && sub_crcl_negative) {
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_WRAPPED_AROUND;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID
                    && rtt_ingress.do_flow_signatures_match) {
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND;
        }

        // Next step for ACK_VALID
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID
                    && rtt_ingress.do_flow_signatures_match) {
            // ACK packet doesn't change flow range right edge
            rtt_ingress.rtt_status_type = RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH;
        }
        // Test
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID) {
            rtt_ingress.rtt_status_type = RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH;
        }

        // Execute flow range right edge register action
        tab_execute_rangetracker_flowrange_rightedge_action.apply();

        // Comparisons of flow range edges
        subtract_for_comparison_rightedges();
        subtract_for_comparison_curr_leftedge_with_mem_rightedge();
        tab_comparison_rightedges.apply();
        tab_comparison_curr_leftedge_with_mem_rightedge.apply();

        // Next step for SEQ_VALID (branch 1: sequence no. wraparound)
        if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_WRAPPED_AROUND) {
            rtt_ingress.left_edge_computed = 1;
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_WRAPAROUND_ADJUSTED;
        }

        // Next step for SEQ_VALID (branch 2: no sequence no. wraparound)
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND && sub_crrr_negative) {
            // Current eACK not ahead of previous eACK: Retransmission, collapse MR
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_FULL_OVERLAP;
            rtt_ingress.left_edge_computed = NULL;
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_COLLAPSED;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND && sub_clrr_zero) {
            // Seq no. == reMR: Extension, leave leMR unchanged if not null, or set to seq no. (effectively do nothing)
            rtt_ingress.left_edge_computed = rtt_ingress.range_record_current.flow_range.left_edge;
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_EXTENSION;
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_PROCEED;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND && sub_clrr_negative) {
            // Seq no. < reMR: Retransmission, set leMR to current eACK
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_PARTIAL_OVERLAP;
            rtt_ingress.left_edge_computed = NULL;
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_COLLAPSED;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND) {
            // Seq no. > reMR: Hole detected, set leMR to Seq no.
            rtt_ingress.left_edge_computed = rtt_ingress.range_record_current.flow_range.left_edge;
            rtt_ingress.rtt_status_type = RTT_STATUS_SEQ_VALID_AND_NO_WRAPAROUND_AND_HOLE;
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_PROCEED;
        }

        // Next step for ACK_VALID
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH && sub_crrr_zero) {
            // Current ACK no. greater than or equal to read right edge: ACK to last transmitted packet or optimistic ACK; close/collapse MR
            rtt_ingress.rtt_status_type = RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK;
            rtt_ingress.left_edge_computed = NULL;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH && sub_crrr_negative) {
            // ACK no. lesser than right edge: Could be one of:
            // (1) ACK no. < left edge : Ignore
            // (2) left edge == ACK no.: Collapse MR
            // (3) ACK no. > left edge: Proceed
            rtt_ingress.rtt_status_type = RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK;
        }

        // Execute flow range left edge register action
        tab_execute_rangetracker_flowrange_leftedge_action.apply();

        subtract_for_comparison_curr_rightedge_with_mem_leftedge();
        tab_comparison_curr_rightedge_with_mem_leftedge.apply();

        // Next step for ACK_VALID (branch 1)
        if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK
                && rtt_ingress.range_record_current.flow_range.left_edge > NULL) {
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_PROCEED;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK) {
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_COLLAPSED;
        }

        // Next step for ACK_VALID (branch 2)
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK
                    && rtt_ingress.range_record_read.flow_range.left_edge > NULL
                    && sub_crrl_zero) {
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_COLLAPSED;
        }
        else if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK
                    && rtt_ingress.range_record_read.flow_range.left_edge > NULL
                    && sub_crrl_positive) {
            rtt_ingress.flow_range_verdict_type = FLOW_RANGE_VERDICT_PROCEED;
        }

        // Determine packet fate
        if (rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_FUTURE_ACK
                || rtt_ingress.rtt_status_type == RTT_STATUS_ACK_VALID_AND_FLOW_SIGNATURES_MATCH_AND_NON_FUTURE_ACK) {
            // ig_tm_md.ucast_egress_port = RTT_REPORT_PORT;
            packet_fate = PKT_FATE_REPORT_EGRESS;
        } else {
            // ig_tm_md.ucast_egress_port = RECIRCULATION_PORT;
            packet_fate = PKT_FATE_RECIRCULATE;
        }

        if (rtt_ingress.rtt_in_type == RTT_IN_TYPE_NONE) {
            packet_fate = PKT_FATE_BYPASS_EGRESS_AND_EGRESS;

        } else {
            act_populate_bridged_metadata();
        }
    }
}