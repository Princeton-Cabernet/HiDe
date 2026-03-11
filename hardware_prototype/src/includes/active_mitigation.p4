// Control block to perform active mitigation

#define HONEYPOT_BYTE_ADVANCE 1000
#define HONEYPOT_RECORD_TIMEOUT 1000000000 // 1 second

typedef bit<REGWIDTH_HONEYPOT> HoneypotWidth_t;
typedef bit<32> HoneypotSignature_t;

struct pair_hsign_tstamp {
    HoneypotSignature_t honeypot_sign;
    Timestamp_t honeypot_tstamp;
}

control Active_Mitigation (
    inout header_t hdr,
    in PortId_t ingress_port,
    in Timestamp_t ingress_timestamp,
    in seq_validity_type_t seq_validity_type,
    in ack_validity_type_t ack_validity_type,
    in TCPSeqNum_t expected_ack,
    in IPv4Addr_t src_prefix,
    in IPv4Addr_t dst_prefix,
    inout packet_fate_type_t packet_fate
) {
    HoneypotWidth_t honeypot_index;
    HoneypotSignature_t honeypot_signature;

    bool is_honeypot_overwritten;
    bool is_honeypot_matched;

    TCPSeqNum_t honeypot_tcp_seqno;
    TCPSeqNum_t honeypot_expected_ack;

    action initialize_module_variables() {
        honeypot_index     = NULL;
        honeypot_signature = NULL;
        
        is_honeypot_overwritten = false;
        is_honeypot_matched     = false;
        
        honeypot_tcp_seqno    = NULL;
        honeypot_expected_ack = NULL;
    }

    Hash<HoneypotWidth_t>(HashAlgorithm_t.CRC16) hash_honeypot_seq_index;
    Hash<HoneypotWidth_t>(HashAlgorithm_t.CRC16) hash_honeypot_ack_index;
    action act_compute_honeypot_seq_index() {
        honeypot_index = hash_honeypot_seq_index.get({dst_prefix});
    }
    action act_compute_honeypot_ack_index() {
        honeypot_index = hash_honeypot_ack_index.get({src_prefix});
    }

    Hash<HoneypotSignature_t>(HashAlgorithm_t.CRC32) hash_honeypot_seq_signature;
    Hash<HoneypotSignature_t>(HashAlgorithm_t.CRC32) hash_honeypot_ack_signature;
    action act_compute_honeypot_seq_signature() {
        honeypot_signature = hash_honeypot_seq_signature.get({
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, honeypot_expected_ack});
    }
    action act_compute_honeypot_ack_signature() {
        honeypot_signature = hash_honeypot_ack_signature.get({
            hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.dst_port, hdr.tcp.src_port, hdr.tcp.ack_no});
    }

    // Honeypot send records register
    Register<pair_hsign_tstamp, _>(REGSIZE_HONEYPOT) reg_honeypot;
    RegisterAction<pair_hsign_tstamp, _, bool>(reg_honeypot) set_honeypot_record = {
        void apply(inout pair_hsign_tstamp mem_cell, out bool ret_val) {
            bool is_empty = (mem_cell.honeypot_sign == NULL);
            bool has_timedout = (ingress_timestamp - mem_cell.honeypot_tstamp > HONEYPOT_RECORD_TIMEOUT);
            if (is_empty || has_timedout) {
                mem_cell.honeypot_sign = honeypot_signature;
                mem_cell.honeypot_tstamp = ingress_timestamp;
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    RegisterAction<pair_hsign_tstamp, _, bool>(reg_honeypot) match_honeypot_record = {
        void apply(inout pair_hsign_tstamp mem_cell, out bool ret_val) {
            if (mem_cell.honeypot_sign == honeypot_signature) {
                mem_cell.honeypot_sign = NULL;
                ret_val = true;
            } else {
                ret_val = false;
            }
        } };
    
    action act_set_reg_honeypot() {
        is_honeypot_overwritten = set_honeypot_record.execute(honeypot_index);
    }
    action act_match_reg_honeypot() {
        is_honeypot_matched = match_honeypot_record.execute(honeypot_index);
    }

    action compute_honeypot_tcp_seqno() {
        @in_hash { honeypot_tcp_seqno = hdr.tcp.seq_no + HONEYPOT_BYTE_ADVANCE; }
    }
    action compute_honeypot_expected_ack() {
        @in_hash { honeypot_expected_ack = expected_ack + HONEYPOT_BYTE_ADVANCE; }
    }

    action set_honeypot_tcp_seqno() {
        @in_hash { hdr.tcp.seq_no = honeypot_tcp_seqno; }
    }

    apply {

        initialize_module_variables();

        if (hdr.tcp.isValid() && (ingress_port == RECIRCULATION_PORT)) {
            // Craft a honeypot packet
            compute_honeypot_tcp_seqno();
            set_honeypot_tcp_seqno();
            packet_fate = PKT_FATE_NORMAL_EGRESS;
        }

        else if (seq_validity_type == SEQ_VALIDITY_HIT) {
            // Check whether a honeypot packet from this flow is already active
            // If not, insert it
            act_compute_honeypot_seq_index();
            compute_honeypot_expected_ack();
            act_compute_honeypot_seq_signature();
            act_set_reg_honeypot();
            
        } else if (ack_validity_type == ACK_VALIDITY_HIT) {
            // Check whether a honeypot ACK has been received
            // If so, clear the slot and blacklist the prefix
            act_compute_honeypot_ack_index();
            act_compute_honeypot_ack_signature();
            act_match_reg_honeypot();
        }

        if (is_honeypot_overwritten) {
            // Honeypot packet needs to be sent out for this prefix
            packet_fate = PKT_FATE_MIRROR_HONEYPOT_AND_EGRESS;
        
        } else if (is_honeypot_matched) {
            // Honeypot ACK was received, blacklist the external prefix
            packet_fate = PKT_FATE_BLACKLIST_AND_DROP;
        }
    }
}