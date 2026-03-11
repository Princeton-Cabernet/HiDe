// Control block to blacklist prefixes

typedef bit<REGWIDTH_BLACKLIST> BlacklistWidth_t;

control Access_Control (
    in header_t hdr,
    in IPv4Addr_t src_prefix,
    in IPv4Addr_t dst_prefix,
    inout packet_fate_type_t packet_fate
) {
    bool is_srcprefix_set;
    bool is_dstprefix_set;
    bool is_srcprefix_match;
    bool is_dstprefix_match;

    BlacklistWidth_t blacklist_srcprefix_index;
    BlacklistWidth_t blacklist_dstprefix_index;

    action initialize_module_variables() {
        is_srcprefix_set   = false;
        is_dstprefix_set   = false;
        is_srcprefix_match = false;
        is_dstprefix_match = false;

        blacklist_srcprefix_index = NULL;
        blacklist_dstprefix_index = NULL;
    }

    Hash<BlacklistWidth_t>(HashAlgorithm_t.CRC32) hash_blacklist_srcprefix_index;
    Hash<BlacklistWidth_t>(HashAlgorithm_t.CRC32) hash_blacklist_dstprefix_index;

    action act_compute_blacklist_srcprefix_index() {
        blacklist_srcprefix_index = hash_blacklist_srcprefix_index.get({src_prefix});
    }
    action act_compute_blacklist_dstprefix_index() {
        blacklist_dstprefix_index = hash_blacklist_dstprefix_index.get({dst_prefix});
    }
    
    Register<IPv4Addr_t, _>(REGSIZE_BLACKLIST) reg_blacklist_srcprefix;
    Register<IPv4Addr_t, _>(REGSIZE_BLACKLIST) reg_blacklist_dstprefix;

    RegisterAction<IPv4Addr_t, _, bool>(reg_blacklist_srcprefix) set_reg_blacklist_srcprefix = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == NULL) {
                mem_cell = src_prefix;
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    RegisterAction<IPv4Addr_t, _, bool>(reg_blacklist_dstprefix) set_reg_blacklist_dstprefix = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == NULL) {
                mem_cell = src_prefix;
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    action act_set_reg_blacklist_srcprefix() {
        is_srcprefix_set = set_reg_blacklist_srcprefix.execute(blacklist_srcprefix_index);
    }
    action act_set_reg_blacklist_dstprefix() {
        is_dstprefix_set = set_reg_blacklist_dstprefix.execute(blacklist_srcprefix_index);
    }
    
    RegisterAction<IPv4Addr_t, _, bool>(reg_blacklist_srcprefix) match_reg_blacklist_srcprefix = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == src_prefix) {
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    RegisterAction<IPv4Addr_t, _, bool>(reg_blacklist_dstprefix) match_reg_blacklist_dstprefix = {
        void apply(inout IPv4Addr_t mem_cell, out bool ret_val) {
            if (mem_cell == dst_prefix) {
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    action act_match_reg_blacklist_srcprefix() {
        is_srcprefix_match = match_reg_blacklist_srcprefix.execute(blacklist_srcprefix_index);
    }
    action act_match_reg_blacklist_dstprefix() {
        is_dstprefix_match = match_reg_blacklist_dstprefix.execute(blacklist_dstprefix_index);
    }

    apply {
        
        initialize_module_variables();

        if (hdr.ipv4.isValid()) {
            act_compute_blacklist_srcprefix_index();
            act_compute_blacklist_dstprefix_index();
        }

        if (hdr.tcp.isValid() && packet_fate == PKT_FATE_BLACKLIST_AND_DROP) {
            act_set_reg_blacklist_srcprefix();
            act_set_reg_blacklist_dstprefix();
        
        } else if (hdr.ipv4.isValid()) {
            act_match_reg_blacklist_srcprefix();
            act_match_reg_blacklist_dstprefix();
        }

        if (is_srcprefix_match || is_dstprefix_match || (packet_fate == PKT_FATE_BLACKLIST_AND_DROP)) {
            packet_fate = PKT_FATE_DROP;
        }
    }
}