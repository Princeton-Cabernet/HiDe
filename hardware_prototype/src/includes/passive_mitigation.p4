// Control block to perform passive mitigation

#define FLOW_RTT_WINDOW_FULL 8w0

const Seed4_t SEED_FLOWTRACKER_INDEX = 11;
const Seed4_t BLOCKLIST_SEED = 13;

// #define SURGE_THRESHOLD     32w75000 // 75 ms (for test trace)
// #define STABILITY_THRESHOLD 32w10000 // 10 ms (for test trace)

// #define SURGE_THRESHOLD     32w4294967295 // infinite
// #define STABILITY_THRESHOLD 32w0 // zero

#define RTT_WINDOW_SIZE 3 // (for testing)
#define SURGE_THRESHOLD     32w90 // 90 ns (for testing)
#define STABILITY_THRESHOLD 32w30 // 30 ns (for testing)

// #define RTT_WINDOW_SIZE 128 // (for live experiment)
// #define SURGE_THRESHOLD     32w9000000 // 8 ms (for live experiment)
// #define STABILITY_THRESHOLD 32w5000000 // 5 ms (for live experiment)

control Passive_Mitigation (
    inout header_t hdr,
    in bool is_recirculated,
    in IPv4Addr_t src_prefix,
    in IPv4Addr_t dst_prefix,
    inout packet_fate_type_t packet_fate
) {

    FlowSignature_t flow_signature;
    FlowTrackerWidth_t flowtracker_index;
    // PrefixSignature_t prefix_signature;
    // PrefixTrackerWidth_t prefixtracker_index;
    PrefixBlockerWidth_t srcprefix_blklist_index;
    PrefixBlockerWidth_t dstprefix_blklist_index;
    bool do_flow_signs_match;
    Counter8_t rtt_count;
    Timestamp_t rtt;
    Timestamp_t min_rtt;
    Timestamp_t last_min_rtt;
    Timestamp_t min_rtt_increase;
    Timestamp_t min_rtt_decrease;
    Timestamp_t sub_minrttincr_surgeth;
    Timestamp_t sub_stableth_minrttincr;
    Timestamp_t sub_stableth_minrttdecr;
    attack_status_type_t attack_status;
    bool do_srcprefixes_match;
    bool do_dstprefixes_match;

    action act_initialize_variables() {
        flow_signature = NULL;
        flowtracker_index = NULL;
        // prefix_signature = NULL;
        // prefixtracker_index = NULL;
        srcprefix_blklist_index = NULL;
        dstprefix_blklist_index = NULL;
        do_flow_signs_match = false;
        rtt_count = NULL;
        rtt = NULL;
        min_rtt = NULL;
        last_min_rtt = NULL;
        min_rtt_increase = NULL;
        min_rtt_decrease = NULL;
        sub_minrttincr_surgeth = 0x1;
        sub_stableth_minrttincr = 0x1;
        sub_stableth_minrttdecr = 0x1;
        attack_status = ATTACK_STATUS_TYPE_INVALID;
        do_srcprefixes_match = false;
        do_dstprefixes_match = false;
    }

    action no_action() { }

    action act_extract_rtt() {
        rtt = hdr.rtt_report.rtt;
    }

    Hash<FlowSignature_t>(HashAlgorithm_t.CRC32,
            CRCPolynomial<FlowSignature_t>(CRC_POLY_3,false,false,false,0,0)) hash_flow_signature;
    action act_compute_flow_signature() {
        flow_signature = hash_flow_signature.get({
            SEED_FLOW_SIGNATURE,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            hdr.rtt_report.src_port,
            hdr.rtt_report.dst_port
        });
    }

    Hash<FlowTrackerWidth_t>(HashAlgorithm_t.CRC16,
            CRCPolynomial<FlowTrackerWidth_t>(CRC_POLY_0,false,false,false,0,0)) hash_flowtracker_index;
    action act_compute_flowtracker_index() {
        flowtracker_index = (FlowTrackerWidth_t)hash_flowtracker_index.get({
            SEED_FLOWTRACKER_INDEX,
            flow_signature
        });
    }

    Register<FlowSignature_t, FlowTrackerWidth_t>(REGSIZE_FLOW_TRACKER) table_flowsign;

    RegisterAction<FlowSignature_t, FlowTrackerWidth_t, bool>(table_flowsign) get_match_table_flowsign = {
        void apply(inout FlowSignature_t mem_cell, out bool ret_val) {
            if (mem_cell == NULL) {
                mem_cell = flow_signature;
                ret_val  = true;
            } else {
                ret_val  = (mem_cell == flow_signature);
            } } };
    action act_get_table_flowsign() {
        do_flow_signs_match = get_match_table_flowsign.execute(flowtracker_index);
    }

    Register<Counter8_t, FlowTrackerWidth_t>(REGSIZE_FLOW_TRACKER) table_rttcount;

    RegisterAction<Counter8_t, FlowTrackerWidth_t, Counter8_t>(table_rttcount) update_table_rttcount = {
        void apply(inout Counter8_t mem_cell, out Counter8_t ret_val) {
            if (mem_cell == RTT_WINDOW_SIZE - 1) {
                mem_cell = 8w0;
            } else {
                mem_cell = mem_cell + 1;
            }
            ret_val = mem_cell;
        } };
    action act_update_table_rttcount() {
        rtt_count = update_table_rttcount.execute(flowtracker_index);
    }

    Register<Timestamp_t, FlowTrackerWidth_t>(REGSIZE_FLOW_TRACKER) table_minrtt;

    RegisterAction<Timestamp_t, FlowTrackerWidth_t, Timestamp_t>(table_minrtt) set_table_minrtt = {
        void apply(inout Timestamp_t mem_cell, out Timestamp_t ret_val) {
            mem_cell = rtt;
            ret_val  = mem_cell;
        } };
    action act_set_table_minrtt() {
        min_rtt = set_table_minrtt.execute(flowtracker_index);
    }

    RegisterAction<Timestamp_t, FlowTrackerWidth_t, Timestamp_t>(table_minrtt) update_and_get_table_minrtt = {
        void apply(inout Timestamp_t mem_cell, out Timestamp_t ret_val) {
            if (mem_cell == NULL || mem_cell > rtt) {
                mem_cell = rtt;
            }
            ret_val = mem_cell;
        } };
    action act_update_and_get_table_minrtt() {
        min_rtt = update_and_get_table_minrtt.execute(flowtracker_index);
    }

    Register<Timestamp_t, FlowTrackerWidth_t>(REGSIZE_FLOW_TRACKER) table_last_minrtt;

    RegisterAction<Timestamp_t, FlowTrackerWidth_t, Timestamp_t>(table_last_minrtt) update_and_get_table_last_minrtt = {
        void apply(inout Timestamp_t mem_cell, out Timestamp_t ret_val) {
            ret_val  = mem_cell;
            mem_cell = min_rtt;
        } };
    action act_update_and_get_table_last_minrtt() {
        last_min_rtt = update_and_get_table_last_minrtt.execute(flowtracker_index);
    }

    action act_compute_min_rtt_increase() {
        min_rtt_increase = min_rtt - last_min_rtt;
    }

    action act_compute_min_rtt_decrease() {
        min_rtt_decrease = last_min_rtt - min_rtt;
    }

    action act_compute_minrttincr_minus_surgeth() {
        sub_minrttincr_surgeth = min_rtt_increase - SURGE_THRESHOLD;
    }

    action act_compute_stableth_minus_minrttincr() {
        sub_stableth_minrttincr = STABILITY_THRESHOLD - min_rtt_increase;
    }

    action act_compute_stableth_minus_minrttdecr() {
        sub_stableth_minrttdecr = STABILITY_THRESHOLD - min_rtt_decrease;
    }

    Register<attack_status_type_t, FlowTrackerWidth_t>(REGSIZE_FLOW_TRACKER) table_attack_status;

    RegisterAction<attack_status_type_t, FlowTrackerWidth_t, attack_status_type_t>(table_attack_status) transition_table_attack_status_to_normal = {
        void apply(inout attack_status_type_t mem_cell, out attack_status_type_t ret_val) {
            if (mem_cell == NULL || mem_cell == ATTACK_STATUS_TYPE_SUSPECTED) {
                mem_cell = ATTACK_STATUS_TYPE_NOATTACK;
            }
            ret_val = mem_cell;
        } };
    RegisterAction<attack_status_type_t, FlowTrackerWidth_t, attack_status_type_t>(table_attack_status) transition_table_attack_status_to_suspected = {
        void apply(inout attack_status_type_t mem_cell, out attack_status_type_t ret_val) {
            if (mem_cell == ATTACK_STATUS_TYPE_NOATTACK) {
                mem_cell = mem_cell + 1;
            }
            ret_val = mem_cell;
        } };
    RegisterAction<attack_status_type_t, FlowTrackerWidth_t, attack_status_type_t>(table_attack_status) transition_table_attack_status_to_confirmed = {
        void apply(inout attack_status_type_t mem_cell, out attack_status_type_t ret_val) {
            if (mem_cell == ATTACK_STATUS_TYPE_SUSPECTED) {
                mem_cell = mem_cell + 1;
            }
            ret_val = mem_cell;
        } };
    RegisterAction<attack_status_type_t, FlowTrackerWidth_t, attack_status_type_t>(table_attack_status) get_table_attack_status = {
        void apply(inout attack_status_type_t mem_cell, out attack_status_type_t ret_val) {
            ret_val = mem_cell;
        } };
    
    action act_set_attack_status_to_normal() {
        attack_status = transition_table_attack_status_to_normal.execute(flowtracker_index);
    }
    action act_set_attack_status_to_suspected() {
        attack_status = transition_table_attack_status_to_suspected.execute(flowtracker_index);
    }
    action act_set_attack_status_to_confirmed() {
        attack_status = transition_table_attack_status_to_confirmed.execute(flowtracker_index);
    }
    action act_get_attack_status() {
        attack_status = get_table_attack_status.execute(flowtracker_index);
    }

    table tab_perform_attack_transition {
        const size = 8;
        key = {
            last_min_rtt:                   ternary;
            min_rtt_increase[31:31]:        ternary;
            min_rtt_decrease[31:31]:        ternary;
            sub_minrttincr_surgeth[31:31]:  ternary;
            sub_stableth_minrttincr[31:31]: ternary;
            sub_stableth_minrttdecr[31:31]: ternary;
        }
        actions = {
            act_set_attack_status_to_normal;
            act_set_attack_status_to_suspected;
            act_set_attack_status_to_confirmed;
            no_action;
        }
        const entries = {
            (NULL, _, _, _, _, _): act_set_attack_status_to_normal();
            (_, 0, _, 0, 1, _):    act_set_attack_status_to_suspected();
            (_, 0, _, 1, 0, _):    act_set_attack_status_to_confirmed();
            (_, 1, 0, _, _, 0):    act_set_attack_status_to_confirmed();
            (_, 0, _, _, 1, _):    act_set_attack_status_to_normal();
            (_, 1, 0, _, _, 1):    act_set_attack_status_to_normal();
        }
        const default_action = no_action();
    }

    Hash<PrefixBlockerWidth_t>(HashAlgorithm_t.CRC16, CRCPolynomial<PrefixBlockerWidth_t>(CRC_POLY_2,false,false,false,0,0)) hash_srcprefix_blklist_index;
    Hash<PrefixBlockerWidth_t>(HashAlgorithm_t.CRC16, CRCPolynomial<PrefixBlockerWidth_t>(CRC_POLY_2,false,false,false,0,0)) hash_dstprefix_blklist_index;

    action act_compute_srcprefix_blocklist_index() {
        srcprefix_blklist_index = hash_srcprefix_blklist_index.get({
            BLOCKLIST_SEED, src_prefix
        });
    }
    action act_compute_dstprefix_blocklist_index() {
        dstprefix_blklist_index = hash_dstprefix_blklist_index.get({
            BLOCKLIST_SEED, dst_prefix
        });
    }
    
    Register<IPv4Addr_t, PrefixBlockerWidth_t>(REGSIZE_PREFIX_BLOCKLIST) table_srcprefix_blocklist;

    RegisterAction<IPv4Addr_t, PrefixBlockerWidth_t, bool>(table_srcprefix_blocklist) set_table_srcprefix_blocklist = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            mem_cell = dst_prefix;
            ret_val  = true;
        } };
    action act_set_table_srcprefix_blocklist() {
        do_srcprefixes_match = set_table_srcprefix_blocklist.execute(dstprefix_blklist_index);
    }
    
    RegisterAction<IPv4Addr_t, PrefixBlockerWidth_t, bool>(table_srcprefix_blocklist) get_match_table_srcprefix_blocklist = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == src_prefix) {
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    action act_get_match_table_srcprefix_blocklist() {
        do_srcprefixes_match = get_match_table_srcprefix_blocklist.execute(srcprefix_blklist_index);
    }

    Register<IPv4Addr_t, PrefixBlockerWidth_t>(REGSIZE_PREFIX_BLOCKLIST) table_dstprefix_blocklist;

    RegisterAction<IPv4Addr_t, PrefixBlockerWidth_t, bool>(table_dstprefix_blocklist) set_table_dstprefix_blocklist = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            mem_cell = dst_prefix;
            ret_val  = true;
        } };
    action act_set_table_dstprefix_blocklist() {
        do_dstprefixes_match = set_table_dstprefix_blocklist.execute(dstprefix_blklist_index);
    }
    
    RegisterAction<IPv4Addr_t, PrefixBlockerWidth_t, bool>(table_dstprefix_blocklist) get_match_table_dstprefix_blocklist = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == dst_prefix) {
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    action act_get_match_table_dstprefix_blocklist() {
        do_dstprefixes_match = get_match_table_dstprefix_blocklist.execute(dstprefix_blklist_index);
    }

    // /* Logging */
    // action act_log_rtt_in_eth_src_addr() {
    //     hdr.ethernet.src_addr = 16w0 ++ eg_md.rtt;
    // }
    // action act_log_min_rtt_in_tcp_seq_no() {
    //     hdr.tcp.seq_no = eg_md.min_rtt;
    // }
    // action act_log_rtt_count_in_tcp_urg_ptr() {
    //     hdr.tcp.urgent_ptr = 8w0 ++ eg_md.rtt_count;
    // }
    // action act_log_min_rtt_in_tcp_ack_no() {
    //     hdr.tcp.ack_no = eg_md.last_min_rtt;
    // }
    // action act_log_attack_status_in_ip_dscp() {
    //     hdr.ipv4.dscp_ecn = attack_status;
    // }
    // action act_log_srcip_blacklist_match_in_ipv4_diffserv() {
    //     hdr.ipv4.diffserv = 7w0 ++ eg_md.srcip_match;
    // }
    action act_log_attack_status() {
        hdr.ipv4.ttl = attack_status;
        hdr.ipv4.dscp_ecn = attack_status;
    }

    apply {

        act_initialize_variables();

        /* Compute flow signature and index for RTT reports */
        if (hdr.rtt_report.isValid() && is_recirculated) {
            act_compute_flow_signature();
            act_compute_flowtracker_index();
            act_get_table_flowsign();
        }
        else {
            do_flow_signs_match = false;
        }

        /* Update "rtt_count" register */
        if (do_flow_signs_match) {
            act_update_table_rttcount();
            act_extract_rtt();
        }
        
        /* Update "last_min_rtt" register if RTT window is full */
        if (do_flow_signs_match && rtt_count == FLOW_RTT_WINDOW_FULL) {
            act_update_and_get_table_minrtt();
            act_update_and_get_table_last_minrtt();
            act_compute_min_rtt_increase();
            act_compute_min_rtt_decrease();
            act_compute_minrttincr_minus_surgeth();
            act_compute_stableth_minus_minrttincr();
            act_compute_stableth_minus_minrttdecr();

        } else if (do_flow_signs_match && rtt_count == 1) {
            act_set_table_minrtt();

        } else if (do_flow_signs_match) {
            act_update_and_get_table_minrtt();
        }

        if (hdr.ipv4.isValid()) {
            act_compute_srcprefix_blocklist_index();
            act_compute_dstprefix_blocklist_index();
        }

        if (do_flow_signs_match && rtt_count == FLOW_RTT_WINDOW_FULL) {
            // Consider attack status change
            tab_perform_attack_transition.apply();
        } else if (hdr.tcp.isValid() || hdr.rtt_report.isValid()) {
            act_get_attack_status();
        }

        if (attack_status == ATTACK_STATUS_TYPE_CONFIRMED) {
            act_set_table_srcprefix_blocklist();
            act_set_table_dstprefix_blocklist();
        
        } else if (hdr.ipv4.isValid()) {
            act_get_match_table_srcprefix_blocklist();
            act_get_match_table_dstprefix_blocklist();
        }

        // Logging
        if (hdr.rtt_report.isValid()) {
        //     act_log_rtt_in_eth_src_addr();
        //     act_log_min_rtt_in_tcp_seq_no();
        //     act_log_rtt_count_in_tcp_urg_ptr();
        //     act_log_min_rtt_in_tcp_ack_no();
            act_log_attack_status();
        //     act_log_srcip_blacklist_match_in_ipv4_diffserv();
        //     act_log_dstip_blacklist_match_in_ipv4_ttl();
        }

        if ((hdr.ipv4.isValid() && !hdr.rtt_report.isValid()) && (do_srcprefixes_match || do_dstprefixes_match)) {
            packet_fate = PKT_FATE_DROP;
        }
    }
}