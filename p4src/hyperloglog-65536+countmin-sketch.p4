/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers-hyperloglog-65536+countmin.p4"
#include "include/parsers.p4"

/* CONSTANTS */

/* Keep exact packet counter for comparison (for evaluation or debugging) */

#define KEEP_EXACT_PACKET_COUNT 0

/* HyperLogLog */

#define HYPERLOGLOG_NUM_REGISTERS_EXPONENT 16
#define HYPERLOGLOG_NUM_REGISTERS (1 << HYPERLOGLOG_NUM_REGISTERS_EXPONENT)
#define HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH 16
#define HYPERLOGLOG_CELL_BIT_WIDTH 5
#define HYPERLOGLOG_HASH_BIT_WIDTH 32
#define HYPERLOGLOG_HASH_VAL_BIT_WIDTH (HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH)

#define HYPERLOGLOG_REGISTER(num) register<bit<HYPERLOGLOG_CELL_BIT_WIDTH>>(HYPERLOGLOG_NUM_REGISTERS) hyperloglog_sketch##num

#define HLL_COUNT_ELSE_IF(n) else if ((bit<HYPERLOGLOG_HASH_VAL_BIT_WIDTH>)meta.hash_val_w[n:0] == meta.hash_val_w) { meta.rho = HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH - n; } \

#define HYPERLOGLOG_COUNT(num, algorithm) hash(meta.hash_val_x, HashAlgorithm.algorithm, (bit<16>)0, \
 {hdr.ipv4.srcAddr}, (bit<32>)4294967295); \
 meta.register_index_j = meta.hash_val_x[(HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH-1):0]; \
 meta.hash_val_w = meta.hash_val_x[31:HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH]; \
 hyperloglog_sketch##num.read(meta.current_register_val_Mj, (bit<32>)meta.register_index_j); \
 if (meta.hash_val_x == 0) { meta.rho = HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH + 1; } \
 HLL_COUNT_ELSE_IF(0) \
 HLL_COUNT_ELSE_IF(1) \
 HLL_COUNT_ELSE_IF(2) \
 HLL_COUNT_ELSE_IF(3) \
 HLL_COUNT_ELSE_IF(4) \
 HLL_COUNT_ELSE_IF(5) \
 HLL_COUNT_ELSE_IF(6) \
 HLL_COUNT_ELSE_IF(7) \
 HLL_COUNT_ELSE_IF(8) \
 HLL_COUNT_ELSE_IF(9) \
 HLL_COUNT_ELSE_IF(10) \
 HLL_COUNT_ELSE_IF(11) \
 HLL_COUNT_ELSE_IF(12) \
 HLL_COUNT_ELSE_IF(13) \
 HLL_COUNT_ELSE_IF(14) \
 else { meta.rho = 1; } \
 if (meta.current_register_val_Mj < meta.rho) { \
    hyperloglog_sketch##num.write((bit<32>)meta.register_index_j, meta.rho); \
 }

/* CountMin */

#define COUNTMIN_NUM_REGISTERS 28
#define COUNTMIN_CELL_BIT_WIDTH 64

#define COUNTMIN_REGISTER(num) register<bit<COUNTMIN_CELL_BIT_WIDTH>>(COUNTMIN_NUM_REGISTERS) countmin_sketch##num

#define COUNTMIN_COUNT(num, algorithm) hash(meta.index_countmin_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.dstAddr}, (bit<32>)COUNTMIN_NUM_REGISTERS);\
 countmin_sketch##num.read(meta.value_countmin_sketch##num, meta.index_countmin_sketch##num); \
 meta.value_countmin_sketch##num = meta.value_countmin_sketch##num +1; \
 countmin_sketch##num.write(meta.index_countmin_sketch##num, meta.value_countmin_sketch##num)

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

    /* For debugging or evaluation purposes */

#if KEEP_EXACT_PACKET_COUNT
    counter(1, CounterType.packets) packet_counter;
#endif

    /* For sketch rollover */

    // TODO Re-implement rollover
    /*register<bit<1>>(1) active_hyperloglog_sketch;
    register<bit<1>>(1) active_countmin_sketch;*/

    /* HyperLogLog */

    HYPERLOGLOG_REGISTER(0);
    HYPERLOGLOG_REGISTER(1);

    /* CountMin */

    COUNTMIN_REGISTER(0);
    COUNTMIN_REGISTER(1);
    COUNTMIN_REGISTER(2);
    COUNTMIN_REGISTER(3);
    COUNTMIN_REGISTER(4);
    COUNTMIN_REGISTER(5);

    action countmin_sketch0_count() {
        COUNTMIN_COUNT(0, crc32_custom);
        COUNTMIN_COUNT(1, crc32_custom);
        COUNTMIN_COUNT(2, crc32_custom);
    }

    action countmin_sketch1_count() {
        COUNTMIN_COUNT(3, crc32_custom);
        COUNTMIN_COUNT(4, crc32_custom);
        COUNTMIN_COUNT(5, crc32_custom);
    }

    /* Basic switch actions */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table repeater {
        key = {
            standard_metadata.ingress_port: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.dstAddr == 0x0A000102) { // 10.0.1.2
#if KEEP_EXACT_PACKET_COUNT
            /* Update packet counter */
            packet_counter.count(0);
#endif

            /* Update HyperLogLog sketch */
            HYPERLOGLOG_COUNT(0, crc32_custom);
            HYPERLOGLOG_COUNT(1, crc32_custom);

            /* Update CountMin sketch */
            countmin_sketch0_count();
            countmin_sketch1_count();
        }

        repeater.apply();
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
