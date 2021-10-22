/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers-4096.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define HYPERLOGLOG_NUM_REGISTERS 4096
#define HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH 12
#define HYPERLOGLOG_CELL_BIT_WIDTH 5
#define HYPERLOGLOG_HASH_BIT_WIDTH 32

#define HYPERLOGLOG_REGISTER() register<bit<HYPERLOGLOG_CELL_BIT_WIDTH>>(HYPERLOGLOG_NUM_REGISTERS) hyperloglog_sketch

#define HYPERLOGLOG_ELSE_IF(n) else if ((bit<20>)meta.hash_val_w[n:0] == meta.hash_val_w) { meta.rho = HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH - n; } \

#define HYPERLOGLOG_COUNT(algorithm) hash(meta.hash_val_x, HashAlgorithm.algorithm, (bit<16>)0, \
 {hdr.ipv4.srcAddr}, (bit<32>)4294967295); \
 meta.register_index_j = meta.hash_val_x[11:0]; \
 meta.hash_val_w = meta.hash_val_x[31:12]; \
 hyperloglog_sketch.read(meta.current_register_val_Mj, (bit<32>)meta.register_index_j); \
 if (meta.hash_val_x == 0) { meta.rho = HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH + 1; } \
 HYPERLOGLOG_ELSE_IF(0) \
 HYPERLOGLOG_ELSE_IF(1) \
 HYPERLOGLOG_ELSE_IF(2) \
 HYPERLOGLOG_ELSE_IF(3) \
 HYPERLOGLOG_ELSE_IF(4) \
 HYPERLOGLOG_ELSE_IF(5) \
 HYPERLOGLOG_ELSE_IF(6) \
 HYPERLOGLOG_ELSE_IF(7) \
 HYPERLOGLOG_ELSE_IF(8) \
 HYPERLOGLOG_ELSE_IF(9) \
 HYPERLOGLOG_ELSE_IF(10) \
 HYPERLOGLOG_ELSE_IF(11) \
 HYPERLOGLOG_ELSE_IF(12) \
 HYPERLOGLOG_ELSE_IF(13) \
 HYPERLOGLOG_ELSE_IF(14) \
 HYPERLOGLOG_ELSE_IF(15) \
 HYPERLOGLOG_ELSE_IF(16) \
 HYPERLOGLOG_ELSE_IF(17) \
 HYPERLOGLOG_ELSE_IF(18) \
 else { meta.rho = 1; } \
 if (meta.current_register_val_Mj < meta.rho) { \
    hyperloglog_sketch.write((bit<32>)meta.register_index_j, meta.rho); \
 }

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    HYPERLOGLOG_REGISTER();
    counter(1, CounterType.packets) packet_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {

        //apply sketch
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            packet_counter.count(0);
            HYPERLOGLOG_COUNT(crc32_custom);
        }

        dmac.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
