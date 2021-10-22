/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers-hyperloglog-16+countmin.p4"
#include "include/parsers.p4"

/* CONSTANTS */

/* Keep exact packet counter for comparison (for evaluation or debugging) */

#define KEEP_EXACT_PACKET_COUNT 1

/* HyperLogLog */

#define HYPERLOGLOG_NUM_REGISTERS_EXPONENT 4
#define HYPERLOGLOG_NUM_REGISTERS (1 << HYPERLOGLOG_NUM_REGISTERS_EXPONENT)
#define HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH HYPERLOGLOG_NUM_REGISTERS_EXPONENT
#define HYPERLOGLOG_CELL_BIT_WIDTH 5
#define HYPERLOGLOG_HASH_BIT_WIDTH 32
#define HYPERLOGLOG_HASH_VAL_BIT_WIDTH (HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH)
#define HYPERLOGLOG_MAX_RHO (HYPERLOGLOG_HASH_BIT_WIDTH + 1 - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH)
/*
 * Estimate must have at least 34 bits to accommodate whole range of possible results of the registers' sum:
 * The minimal summand is 2^(-(L + 1 - \log_2(m))). Therefore, for m = 16 and L = 32, 29 bits past the "point" are required.
 * The maximal sum is m * 2^0 = m. Therefore, for m = 16, 5 bits before the "point" are required.
 *
 * Additionally, largest estimate produced by small range correction is 35 bits long.
 *
 * Therefore, HYPERLOGLOG_ESTIMATE_BIT_WIDTH is 35.
 */
#define HYPERLOGLOG_ESTIMATE_BIT_WIDTH 35
#define HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD 2312410000 // 1/(2.5 * 16 / (0.673 * 16**2)) << 29
#define HYPERLOGLOG_DDOS_THRESHOLD 92496400 // equiv. to 1000, calculated as (1000/(0.673 * 16^2))^(-1) << 29

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
 HLL_COUNT_ELSE_IF(15) \
 HLL_COUNT_ELSE_IF(16) \
 HLL_COUNT_ELSE_IF(17) \
 HLL_COUNT_ELSE_IF(18) \
 HLL_COUNT_ELSE_IF(19) \
 HLL_COUNT_ELSE_IF(20) \
 HLL_COUNT_ELSE_IF(21) \
 HLL_COUNT_ELSE_IF(22) \
 HLL_COUNT_ELSE_IF(23) \
 HLL_COUNT_ELSE_IF(24) \
 HLL_COUNT_ELSE_IF(25) \
 HLL_COUNT_ELSE_IF(26) \
 else { meta.rho = 1; } \
 if (meta.current_register_val_Mj < meta.rho) { \
    hyperloglog_sketch##num.write((bit<32>)meta.register_index_j, meta.rho); \
 }

#define HLL_EST_ADD_REGISTER(n) hyperloglog_sketch0.read(hll_value, n); \
 if (hll_value == 0) { hll_sum = hll_sum + (1 << HYPERLOGLOG_MAX_RHO); number_of_empty_registers = number_of_empty_registers + 1; } \
 else { hll_sum = hll_sum + (bit<HYPERLOGLOG_ESTIMATE_BIT_WIDTH>)(1 << (HYPERLOGLOG_MAX_RHO - hll_value)); }

 /* CountMin */

#define COUNTMIN_NUM_REGISTERS 28
#define COUNTMIN_CELL_BIT_WIDTH 64

#define COUNTMIN_DDOS_THRESHOLD 100000

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

    /* DDoS detection */

    register<bit<1>>(1) ddos_detected;
    register<bit<4>>(1) packets_seen;

    /* HyperLogLog */

    HYPERLOGLOG_REGISTER(0);
    HYPERLOGLOG_REGISTER(1);
    register<bit<HYPERLOGLOG_ESTIMATE_BIT_WIDTH>>(1) hyperloglog_est;
    register<bit<1>>(1) small_range_correction_applied;

    /* CountMin */

    COUNTMIN_REGISTER(0);
    COUNTMIN_REGISTER(1);
    COUNTMIN_REGISTER(2);
    COUNTMIN_REGISTER(3);
    COUNTMIN_REGISTER(4);
    COUNTMIN_REGISTER(5);
    register<bit<64>>(1) countmin_est;

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

    /* DDoS detection actions */

    action sketch_thresholds_exceeded() {
        clone(CloneType.I2E, 100);
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

            /* Update HyperLogLog sketches */
            HYPERLOGLOG_COUNT(0, crc32_custom);
            HYPERLOGLOG_COUNT(1, crc32_custom);

            /* Update CountMin sketches */
            countmin_sketch0_count();
            countmin_sketch1_count();

            bit<4> packet_count;
            packets_seen.read(packet_count, 0);
            packet_count = packet_count + 1;
            packets_seen.write(0, packet_count);

            /* Evaluate sketches only every 10 packets */
            if (packet_count == 10) {
                // Reset the count
                packets_seen.write(0, 0);

                /* Calculate HyperLogLog estimate */
                bit<HYPERLOGLOG_CELL_BIT_WIDTH> hll_value;
                bit<HYPERLOGLOG_ESTIMATE_BIT_WIDTH> hll_sum = 0;
                bit<HYPERLOGLOG_NUM_REGISTERS_EXPONENT> number_of_empty_registers = 0;
                /* begin repeat for each register */
                HLL_EST_ADD_REGISTER(0)
                HLL_EST_ADD_REGISTER(1)
                HLL_EST_ADD_REGISTER(2)
                HLL_EST_ADD_REGISTER(3)
                HLL_EST_ADD_REGISTER(4)
                HLL_EST_ADD_REGISTER(5)
                HLL_EST_ADD_REGISTER(6)
                HLL_EST_ADD_REGISTER(7)
                HLL_EST_ADD_REGISTER(8)
                HLL_EST_ADD_REGISTER(9)
                HLL_EST_ADD_REGISTER(10)
                HLL_EST_ADD_REGISTER(11)
                HLL_EST_ADD_REGISTER(12)
                HLL_EST_ADD_REGISTER(13)
                HLL_EST_ADD_REGISTER(14)
                HLL_EST_ADD_REGISTER(15)
                /* end repeat */

                bit<HYPERLOGLOG_ESTIMATE_BIT_WIDTH> hll_result;

                if (hll_sum >= HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD) {
                /* 
                * Apply small range correction:
                * E = m * log(m/V)
                * where V is the number of empty registers (between 0 and m)
                */
                small_range_correction_applied.write(0, 1);
                if (number_of_empty_registers == 0) { small_range_correction_applied.write(0, 0); hll_result = hll_sum; }
                else if (number_of_empty_registers == 1) { hll_result = 35w23816355774; }
                else if (number_of_empty_registers == 2) { hll_result = 35w17862266830; }
                else if (number_of_empty_registers == 3) { hll_result = 35w14379348072; }
                else if (number_of_empty_registers == 4) { hll_result = 35w11908177887; }
                else if (number_of_empty_registers == 5) { hll_result = 35w9991389376; }
                else if (number_of_empty_registers == 6) { hll_result = 35w8425259129; }
                else if (number_of_empty_registers == 7) { hll_result = 35w7101114872; }
                else if (number_of_empty_registers == 8) { hll_result = 35w5954088943; }
                else if (number_of_empty_registers == 9) { hll_result = 35w4942340371; }
                else if (number_of_empty_registers == 10) { hll_result = 35w4037300433; }
                else if (number_of_empty_registers == 11) { hll_result = 35w3218592222; }
                else if (number_of_empty_registers == 12) { hll_result = 35w2471170185; }
                else if (number_of_empty_registers == 13) { hll_result = 35w1783608562; }
                else if (number_of_empty_registers == 14) { hll_result = 35w1147025928; }
                else if (number_of_empty_registers == 15) { hll_result = 35w554381675; }
                else { hll_result = 0; }
                } else {
                small_range_correction_applied.write(0, 0);
                hll_result = hll_sum;
                }

                hyperloglog_est.write(0, hll_result);

                /* Get CountMin estimate */
                bit<64> countmin_result;
                if (meta.value_countmin_sketch0 <= meta.value_countmin_sketch1) {
                    if (meta.value_countmin_sketch0 <= meta.value_countmin_sketch2) {
                        countmin_result = meta.value_countmin_sketch0;
                    } else {
                        countmin_result = meta.value_countmin_sketch2;
                    }
                } else {
                    if (meta.value_countmin_sketch1 <= meta.value_countmin_sketch2) {
                        countmin_result = meta.value_countmin_sketch1;
                    } else {
                        countmin_result = meta.value_countmin_sketch2;
                    }
                }
                countmin_est.write(0, countmin_result);

                /* Notify controller if necessary */
                bit<1> ddos;
                ddos_detected.read(ddos, 0);

                if (ddos == 0 && hll_result < HYPERLOGLOG_DDOS_THRESHOLD && countmin_result > COUNTMIN_DDOS_THRESHOLD) {
                    ddos_detected.write(0, 1);
                    sketch_thresholds_exceeded();
                }
            }
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
    apply {
        // If ingress clone
        if (standard_metadata.instance_type == 1) {
            hdr.ethernet.etherType = 0x1234; // used by controller to filter packets
        }
    }
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
