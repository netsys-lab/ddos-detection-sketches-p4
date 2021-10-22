/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers-hyperloglog-256+countmin.p4"
#include "include/parsers.p4"

/* CONSTANTS */

/* Keep exact packet counter for comparison (for evaluation or debugging) */

#define KEEP_EXACT_PACKET_COUNT 1

/* HyperLogLog */

#define HYPERLOGLOG_NUM_REGISTERS_EXPONENT 8
#define HYPERLOGLOG_NUM_REGISTERS (1 << HYPERLOGLOG_NUM_REGISTERS_EXPONENT)
#define HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH HYPERLOGLOG_NUM_REGISTERS_EXPONENT
#define HYPERLOGLOG_CELL_BIT_WIDTH 5
#define HYPERLOGLOG_HASH_BIT_WIDTH 32
#define HYPERLOGLOG_HASH_VAL_BIT_WIDTH (HYPERLOGLOG_HASH_BIT_WIDTH - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH)
#define HYPERLOGLOG_MAX_RHO (HYPERLOGLOG_HASH_BIT_WIDTH + 1 - HYPERLOGLOG_REGISTER_INDEX_BIT_WIDTH)
/*
 * Estimate must have at least 34 bits to accommodate whole range of possible results of the registers' sum:
 * The minimal summand is 2^(-(L + 1 - \log_2(m))). Therefore, for m = 256 and L = 32, 25 bits past the "point" are required.
 * The maximal sum is m * 2^0 = m. Therefore, for m = 256, 9 bits before the "point" are required.
 *
 * Additionally, largest estimate produced by small range correction is 36 bits long.
 *
 * Therefore, HYPERLOGLOG_ESTIMATE_BIT_WIDTH is 36.
 */
#define HYPERLOGLOG_ESTIMATE_BIT_WIDTH 36
#define HYPERLOGLOG_SMALL_RANGE_CORRECTION_THRESHOLD 2467970000 // 1/(2.5 * 256 / (0.7213/(1 + 1.079/256) * 256**2)) << 25
#define HYPERLOGLOG_DDOS_THRESHOLD 1579500000 // equiv. to 1000, calculated as (1000/(0.7213/(1 + 1.079/256) * 256^2))^(-1) << 25

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
                HLL_EST_ADD_REGISTER(16)
                HLL_EST_ADD_REGISTER(17)
                HLL_EST_ADD_REGISTER(18)
                HLL_EST_ADD_REGISTER(19)
                HLL_EST_ADD_REGISTER(20)
                HLL_EST_ADD_REGISTER(21)
                HLL_EST_ADD_REGISTER(22)
                HLL_EST_ADD_REGISTER(23)
                HLL_EST_ADD_REGISTER(24)
                HLL_EST_ADD_REGISTER(25)
                HLL_EST_ADD_REGISTER(26)
                HLL_EST_ADD_REGISTER(27)
                HLL_EST_ADD_REGISTER(28)
                HLL_EST_ADD_REGISTER(29)
                HLL_EST_ADD_REGISTER(30)
                HLL_EST_ADD_REGISTER(31)
                HLL_EST_ADD_REGISTER(32)
                HLL_EST_ADD_REGISTER(33)
                HLL_EST_ADD_REGISTER(34)
                HLL_EST_ADD_REGISTER(35)
                HLL_EST_ADD_REGISTER(36)
                HLL_EST_ADD_REGISTER(37)
                HLL_EST_ADD_REGISTER(38)
                HLL_EST_ADD_REGISTER(39)
                HLL_EST_ADD_REGISTER(40)
                HLL_EST_ADD_REGISTER(41)
                HLL_EST_ADD_REGISTER(42)
                HLL_EST_ADD_REGISTER(43)
                HLL_EST_ADD_REGISTER(44)
                HLL_EST_ADD_REGISTER(45)
                HLL_EST_ADD_REGISTER(46)
                HLL_EST_ADD_REGISTER(47)
                HLL_EST_ADD_REGISTER(48)
                HLL_EST_ADD_REGISTER(49)
                HLL_EST_ADD_REGISTER(50)
                HLL_EST_ADD_REGISTER(51)
                HLL_EST_ADD_REGISTER(52)
                HLL_EST_ADD_REGISTER(53)
                HLL_EST_ADD_REGISTER(54)
                HLL_EST_ADD_REGISTER(55)
                HLL_EST_ADD_REGISTER(56)
                HLL_EST_ADD_REGISTER(57)
                HLL_EST_ADD_REGISTER(58)
                HLL_EST_ADD_REGISTER(59)
                HLL_EST_ADD_REGISTER(60)
                HLL_EST_ADD_REGISTER(61)
                HLL_EST_ADD_REGISTER(62)
                HLL_EST_ADD_REGISTER(63)
                HLL_EST_ADD_REGISTER(64)
                HLL_EST_ADD_REGISTER(65)
                HLL_EST_ADD_REGISTER(66)
                HLL_EST_ADD_REGISTER(67)
                HLL_EST_ADD_REGISTER(68)
                HLL_EST_ADD_REGISTER(69)
                HLL_EST_ADD_REGISTER(70)
                HLL_EST_ADD_REGISTER(71)
                HLL_EST_ADD_REGISTER(72)
                HLL_EST_ADD_REGISTER(73)
                HLL_EST_ADD_REGISTER(74)
                HLL_EST_ADD_REGISTER(75)
                HLL_EST_ADD_REGISTER(76)
                HLL_EST_ADD_REGISTER(77)
                HLL_EST_ADD_REGISTER(78)
                HLL_EST_ADD_REGISTER(79)
                HLL_EST_ADD_REGISTER(80)
                HLL_EST_ADD_REGISTER(81)
                HLL_EST_ADD_REGISTER(82)
                HLL_EST_ADD_REGISTER(83)
                HLL_EST_ADD_REGISTER(84)
                HLL_EST_ADD_REGISTER(85)
                HLL_EST_ADD_REGISTER(86)
                HLL_EST_ADD_REGISTER(87)
                HLL_EST_ADD_REGISTER(88)
                HLL_EST_ADD_REGISTER(89)
                HLL_EST_ADD_REGISTER(90)
                HLL_EST_ADD_REGISTER(91)
                HLL_EST_ADD_REGISTER(92)
                HLL_EST_ADD_REGISTER(93)
                HLL_EST_ADD_REGISTER(94)
                HLL_EST_ADD_REGISTER(95)
                HLL_EST_ADD_REGISTER(96)
                HLL_EST_ADD_REGISTER(97)
                HLL_EST_ADD_REGISTER(98)
                HLL_EST_ADD_REGISTER(99)
                HLL_EST_ADD_REGISTER(100)
                HLL_EST_ADD_REGISTER(101)
                HLL_EST_ADD_REGISTER(102)
                HLL_EST_ADD_REGISTER(103)
                HLL_EST_ADD_REGISTER(104)
                HLL_EST_ADD_REGISTER(105)
                HLL_EST_ADD_REGISTER(106)
                HLL_EST_ADD_REGISTER(107)
                HLL_EST_ADD_REGISTER(108)
                HLL_EST_ADD_REGISTER(109)
                HLL_EST_ADD_REGISTER(110)
                HLL_EST_ADD_REGISTER(111)
                HLL_EST_ADD_REGISTER(112)
                HLL_EST_ADD_REGISTER(113)
                HLL_EST_ADD_REGISTER(114)
                HLL_EST_ADD_REGISTER(115)
                HLL_EST_ADD_REGISTER(116)
                HLL_EST_ADD_REGISTER(117)
                HLL_EST_ADD_REGISTER(118)
                HLL_EST_ADD_REGISTER(119)
                HLL_EST_ADD_REGISTER(120)
                HLL_EST_ADD_REGISTER(121)
                HLL_EST_ADD_REGISTER(122)
                HLL_EST_ADD_REGISTER(123)
                HLL_EST_ADD_REGISTER(124)
                HLL_EST_ADD_REGISTER(125)
                HLL_EST_ADD_REGISTER(126)
                HLL_EST_ADD_REGISTER(127)
                HLL_EST_ADD_REGISTER(128)
                HLL_EST_ADD_REGISTER(129)
                HLL_EST_ADD_REGISTER(130)
                HLL_EST_ADD_REGISTER(131)
                HLL_EST_ADD_REGISTER(132)
                HLL_EST_ADD_REGISTER(133)
                HLL_EST_ADD_REGISTER(134)
                HLL_EST_ADD_REGISTER(135)
                HLL_EST_ADD_REGISTER(136)
                HLL_EST_ADD_REGISTER(137)
                HLL_EST_ADD_REGISTER(138)
                HLL_EST_ADD_REGISTER(139)
                HLL_EST_ADD_REGISTER(140)
                HLL_EST_ADD_REGISTER(141)
                HLL_EST_ADD_REGISTER(142)
                HLL_EST_ADD_REGISTER(143)
                HLL_EST_ADD_REGISTER(144)
                HLL_EST_ADD_REGISTER(145)
                HLL_EST_ADD_REGISTER(146)
                HLL_EST_ADD_REGISTER(147)
                HLL_EST_ADD_REGISTER(148)
                HLL_EST_ADD_REGISTER(149)
                HLL_EST_ADD_REGISTER(150)
                HLL_EST_ADD_REGISTER(151)
                HLL_EST_ADD_REGISTER(152)
                HLL_EST_ADD_REGISTER(153)
                HLL_EST_ADD_REGISTER(154)
                HLL_EST_ADD_REGISTER(155)
                HLL_EST_ADD_REGISTER(156)
                HLL_EST_ADD_REGISTER(157)
                HLL_EST_ADD_REGISTER(158)
                HLL_EST_ADD_REGISTER(159)
                HLL_EST_ADD_REGISTER(160)
                HLL_EST_ADD_REGISTER(161)
                HLL_EST_ADD_REGISTER(162)
                HLL_EST_ADD_REGISTER(163)
                HLL_EST_ADD_REGISTER(164)
                HLL_EST_ADD_REGISTER(165)
                HLL_EST_ADD_REGISTER(166)
                HLL_EST_ADD_REGISTER(167)
                HLL_EST_ADD_REGISTER(168)
                HLL_EST_ADD_REGISTER(169)
                HLL_EST_ADD_REGISTER(170)
                HLL_EST_ADD_REGISTER(171)
                HLL_EST_ADD_REGISTER(172)
                HLL_EST_ADD_REGISTER(173)
                HLL_EST_ADD_REGISTER(174)
                HLL_EST_ADD_REGISTER(175)
                HLL_EST_ADD_REGISTER(176)
                HLL_EST_ADD_REGISTER(177)
                HLL_EST_ADD_REGISTER(178)
                HLL_EST_ADD_REGISTER(179)
                HLL_EST_ADD_REGISTER(180)
                HLL_EST_ADD_REGISTER(181)
                HLL_EST_ADD_REGISTER(182)
                HLL_EST_ADD_REGISTER(183)
                HLL_EST_ADD_REGISTER(184)
                HLL_EST_ADD_REGISTER(185)
                HLL_EST_ADD_REGISTER(186)
                HLL_EST_ADD_REGISTER(187)
                HLL_EST_ADD_REGISTER(188)
                HLL_EST_ADD_REGISTER(189)
                HLL_EST_ADD_REGISTER(190)
                HLL_EST_ADD_REGISTER(191)
                HLL_EST_ADD_REGISTER(192)
                HLL_EST_ADD_REGISTER(193)
                HLL_EST_ADD_REGISTER(194)
                HLL_EST_ADD_REGISTER(195)
                HLL_EST_ADD_REGISTER(196)
                HLL_EST_ADD_REGISTER(197)
                HLL_EST_ADD_REGISTER(198)
                HLL_EST_ADD_REGISTER(199)
                HLL_EST_ADD_REGISTER(200)
                HLL_EST_ADD_REGISTER(201)
                HLL_EST_ADD_REGISTER(202)
                HLL_EST_ADD_REGISTER(203)
                HLL_EST_ADD_REGISTER(204)
                HLL_EST_ADD_REGISTER(205)
                HLL_EST_ADD_REGISTER(206)
                HLL_EST_ADD_REGISTER(207)
                HLL_EST_ADD_REGISTER(208)
                HLL_EST_ADD_REGISTER(209)
                HLL_EST_ADD_REGISTER(210)
                HLL_EST_ADD_REGISTER(211)
                HLL_EST_ADD_REGISTER(212)
                HLL_EST_ADD_REGISTER(213)
                HLL_EST_ADD_REGISTER(214)
                HLL_EST_ADD_REGISTER(215)
                HLL_EST_ADD_REGISTER(216)
                HLL_EST_ADD_REGISTER(217)
                HLL_EST_ADD_REGISTER(218)
                HLL_EST_ADD_REGISTER(219)
                HLL_EST_ADD_REGISTER(220)
                HLL_EST_ADD_REGISTER(221)
                HLL_EST_ADD_REGISTER(222)
                HLL_EST_ADD_REGISTER(223)
                HLL_EST_ADD_REGISTER(224)
                HLL_EST_ADD_REGISTER(225)
                HLL_EST_ADD_REGISTER(226)
                HLL_EST_ADD_REGISTER(227)
                HLL_EST_ADD_REGISTER(228)
                HLL_EST_ADD_REGISTER(229)
                HLL_EST_ADD_REGISTER(230)
                HLL_EST_ADD_REGISTER(231)
                HLL_EST_ADD_REGISTER(232)
                HLL_EST_ADD_REGISTER(233)
                HLL_EST_ADD_REGISTER(234)
                HLL_EST_ADD_REGISTER(235)
                HLL_EST_ADD_REGISTER(236)
                HLL_EST_ADD_REGISTER(237)
                HLL_EST_ADD_REGISTER(238)
                HLL_EST_ADD_REGISTER(239)
                HLL_EST_ADD_REGISTER(240)
                HLL_EST_ADD_REGISTER(241)
                HLL_EST_ADD_REGISTER(242)
                HLL_EST_ADD_REGISTER(243)
                HLL_EST_ADD_REGISTER(244)
                HLL_EST_ADD_REGISTER(245)
                HLL_EST_ADD_REGISTER(246)
                HLL_EST_ADD_REGISTER(247)
                HLL_EST_ADD_REGISTER(248)
                HLL_EST_ADD_REGISTER(249)
                HLL_EST_ADD_REGISTER(250)
                HLL_EST_ADD_REGISTER(251)
                HLL_EST_ADD_REGISTER(252)
                HLL_EST_ADD_REGISTER(253)
                HLL_EST_ADD_REGISTER(254)
                HLL_EST_ADD_REGISTER(255)
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
                else if (number_of_empty_registers == 1) { hll_result = 36w47632711549; }
                else if (number_of_empty_registers == 2) { hll_result = 36w41678622605; }
                else if (number_of_empty_registers == 3) { hll_result = 36w38195703847; }
                else if (number_of_empty_registers == 4) { hll_result = 36w35724533661; }
                else if (number_of_empty_registers == 5) { hll_result = 36w33807745151; }
                else if (number_of_empty_registers == 6) { hll_result = 36w32241614903; }
                else if (number_of_empty_registers == 7) { hll_result = 36w30917470646; }
                else if (number_of_empty_registers == 8) { hll_result = 36w29770444718; }
                else if (number_of_empty_registers == 9) { hll_result = 36w28758696145; }
                else if (number_of_empty_registers == 10) { hll_result = 36w27853656207; }
                else if (number_of_empty_registers == 11) { hll_result = 36w27034947997; }
                else if (number_of_empty_registers == 12) { hll_result = 36w26287525960; }
                else if (number_of_empty_registers == 13) { hll_result = 36w25599964336; }
                else if (number_of_empty_registers == 14) { hll_result = 36w24963381703; }
                else if (number_of_empty_registers == 15) { hll_result = 36w24370737449; }
                else if (number_of_empty_registers == 16) { hll_result = 36w23816355774; }
                else if (number_of_empty_registers == 17) { hll_result = 36w23295594238; }
                else if (number_of_empty_registers == 18) { hll_result = 36w22804607202; }
                else if (number_of_empty_registers == 19) { hll_result = 36w22340173307; }
                else if (number_of_empty_registers == 20) { hll_result = 36w21899567264; }
                else if (number_of_empty_registers == 21) { hll_result = 36w21480462945; }
                else if (number_of_empty_registers == 22) { hll_result = 36w21080859053; }
                else if (number_of_empty_registers == 23) { hll_result = 36w20699021320; }
                else if (number_of_empty_registers == 24) { hll_result = 36w20333437016; }
                else if (number_of_empty_registers == 25) { hll_result = 36w19982778753; }
                else if (number_of_empty_registers == 26) { hll_result = 36w19645875393; }
                else if (number_of_empty_registers == 27) { hll_result = 36w19321688444; }
                else if (number_of_empty_registers == 28) { hll_result = 36w19009292759; }
                else if (number_of_empty_registers == 29) { hll_result = 36w18707860617; }
                else if (number_of_empty_registers == 30) { hll_result = 36w18416648506; }
                else if (number_of_empty_registers == 31) { hll_result = 36w18134986072; }
                else if (number_of_empty_registers == 32) { hll_result = 36w17862266830; }
                else if (number_of_empty_registers == 33) { hll_result = 36w17597940295; }
                else if (number_of_empty_registers == 34) { hll_result = 36w17341505294; }
                else if (number_of_empty_registers == 35) { hll_result = 36w17092504249; }
                else if (number_of_empty_registers == 36) { hll_result = 36w16850518258; }
                else if (number_of_empty_registers == 37) { hll_result = 36w16615162862; }
                else if (number_of_empty_registers == 38) { hll_result = 36w16386084364; }
                else if (number_of_empty_registers == 39) { hll_result = 36w16162956635; }
                else if (number_of_empty_registers == 40) { hll_result = 36w15945478320; }
                else if (number_of_empty_registers == 41) { hll_result = 36w15733370393; }
                else if (number_of_empty_registers == 42) { hll_result = 36w15526374001; }
                else if (number_of_empty_registers == 43) { hll_result = 36w15324248567; }
                else if (number_of_empty_registers == 44) { hll_result = 36w15126770110; }
                else if (number_of_empty_registers == 45) { hll_result = 36w14933729748; }
                else if (number_of_empty_registers == 46) { hll_result = 36w14744932377; }
                else if (number_of_empty_registers == 47) { hll_result = 36w14560195480; }
                else if (number_of_empty_registers == 48) { hll_result = 36w14379348072; }
                else if (number_of_empty_registers == 49) { hll_result = 36w14202229744; }
                else if (number_of_empty_registers == 50) { hll_result = 36w14028689810; }
                else if (number_of_empty_registers == 51) { hll_result = 36w13858586536; }
                else if (number_of_empty_registers == 52) { hll_result = 36w13691786449; }
                else if (number_of_empty_registers == 53) { hll_result = 36w13528163700; }
                else if (number_of_empty_registers == 54) { hll_result = 36w13367599500; }
                else if (number_of_empty_registers == 55) { hll_result = 36w13209981599; }
                else if (number_of_empty_registers == 56) { hll_result = 36w13055203815; }
                else if (number_of_empty_registers == 57) { hll_result = 36w12903165606; }
                else if (number_of_empty_registers == 58) { hll_result = 36w12753771673; }
                else if (number_of_empty_registers == 59) { hll_result = 36w12606931609; }
                else if (number_of_empty_registers == 60) { hll_result = 36w12462559562; }
                else if (number_of_empty_registers == 61) { hll_result = 36w12320573939; }
                else if (number_of_empty_registers == 62) { hll_result = 36w12180897129; }
                else if (number_of_empty_registers == 63) { hll_result = 36w12043455243; }
                else if (number_of_empty_registers == 64) { hll_result = 36w11908177887; }
                else if (number_of_empty_registers == 65) { hll_result = 36w11774997939; }
                else if (number_of_empty_registers == 66) { hll_result = 36w11643851352; }
                else if (number_of_empty_registers == 67) { hll_result = 36w11514676969; }
                else if (number_of_empty_registers == 68) { hll_result = 36w11387416351; }
                else if (number_of_empty_registers == 69) { hll_result = 36w11262013619; }
                else if (number_of_empty_registers == 70) { hll_result = 36w11138415305; }
                else if (number_of_empty_registers == 71) { hll_result = 36w11016570218; }
                else if (number_of_empty_registers == 72) { hll_result = 36w10896429314; }
                else if (number_of_empty_registers == 73) { hll_result = 36w10777945580; }
                else if (number_of_empty_registers == 74) { hll_result = 36w10661073918; }
                else if (number_of_empty_registers == 75) { hll_result = 36w10545771052; }
                else if (number_of_empty_registers == 76) { hll_result = 36w10431995420; }
                else if (number_of_empty_registers == 77) { hll_result = 36w10319707095; }
                else if (number_of_empty_registers == 78) { hll_result = 36w10208867691; }
                else if (number_of_empty_registers == 79) { hll_result = 36w10099440293; }
                else if (number_of_empty_registers == 80) { hll_result = 36w9991389376; }
                else if (number_of_empty_registers == 81) { hll_result = 36w9884680742; }
                else if (number_of_empty_registers == 82) { hll_result = 36w9779281449; }
                else if (number_of_empty_registers == 83) { hll_result = 36w9675159755; }
                else if (number_of_empty_registers == 84) { hll_result = 36w9572285057; }
                else if (number_of_empty_registers == 85) { hll_result = 36w9470627840; }
                else if (number_of_empty_registers == 86) { hll_result = 36w9370159624; }
                else if (number_of_empty_registers == 87) { hll_result = 36w9270852915; }
                else if (number_of_empty_registers == 88) { hll_result = 36w9172681166; }
                else if (number_of_empty_registers == 89) { hll_result = 36w9075618725; }
                else if (number_of_empty_registers == 90) { hll_result = 36w8979640804; }
                else if (number_of_empty_registers == 91) { hll_result = 36w8884723434; }
                else if (number_of_empty_registers == 92) { hll_result = 36w8790843433; }
                else if (number_of_empty_registers == 93) { hll_result = 36w8697978371; }
                else if (number_of_empty_registers == 94) { hll_result = 36w8606106537; }
                else if (number_of_empty_registers == 95) { hll_result = 36w8515206910; }
                else if (number_of_empty_registers == 96) { hll_result = 36w8425259129; }
                else if (number_of_empty_registers == 97) { hll_result = 36w8336243466; }
                else if (number_of_empty_registers == 98) { hll_result = 36w8248140800; }
                else if (number_of_empty_registers == 99) { hll_result = 36w8160932594; }
                else if (number_of_empty_registers == 100) { hll_result = 36w8074600866; }
                else if (number_of_empty_registers == 101) { hll_result = 36w7989128175; }
                else if (number_of_empty_registers == 102) { hll_result = 36w7904497593; }
                else if (number_of_empty_registers == 103) { hll_result = 36w7820692688; }
                else if (number_of_empty_registers == 104) { hll_result = 36w7737697505; }
                else if (number_of_empty_registers == 105) { hll_result = 36w7655496547; }
                else if (number_of_empty_registers == 106) { hll_result = 36w7574074756; }
                else if (number_of_empty_registers == 107) { hll_result = 36w7493417501; }
                else if (number_of_empty_registers == 108) { hll_result = 36w7413510556; }
                else if (number_of_empty_registers == 109) { hll_result = 36w7334340092; }
                else if (number_of_empty_registers == 110) { hll_result = 36w7255892655; }
                else if (number_of_empty_registers == 111) { hll_result = 36w7178155160; }
                else if (number_of_empty_registers == 112) { hll_result = 36w7101114872; }
                else if (number_of_empty_registers == 113) { hll_result = 36w7024759395; }
                else if (number_of_empty_registers == 114) { hll_result = 36w6949076662; }
                else if (number_of_empty_registers == 115) { hll_result = 36w6874054922; }
                else if (number_of_empty_registers == 116) { hll_result = 36w6799682730; }
                else if (number_of_empty_registers == 117) { hll_result = 36w6725948933; }
                else if (number_of_empty_registers == 118) { hll_result = 36w6652842665; }
                else if (number_of_empty_registers == 119) { hll_result = 36w6580353336; }
                else if (number_of_empty_registers == 120) { hll_result = 36w6508470618; }
                else if (number_of_empty_registers == 121) { hll_result = 36w6437184445; }
                else if (number_of_empty_registers == 122) { hll_result = 36w6366484996; }
                else if (number_of_empty_registers == 123) { hll_result = 36w6296362691; }
                else if (number_of_empty_registers == 124) { hll_result = 36w6226808185; }
                else if (number_of_empty_registers == 125) { hll_result = 36w6157812356; }
                else if (number_of_empty_registers == 126) { hll_result = 36w6089366299; }
                else if (number_of_empty_registers == 127) { hll_result = 36w6021461325; }
                else if (number_of_empty_registers == 128) { hll_result = 36w5954088943; }
                else if (number_of_empty_registers == 129) { hll_result = 36w5887240866; }
                else if (number_of_empty_registers == 130) { hll_result = 36w5820908995; }
                else if (number_of_empty_registers == 131) { hll_result = 36w5755085419; }
                else if (number_of_empty_registers == 132) { hll_result = 36w5689762408; }
                else if (number_of_empty_registers == 133) { hll_result = 36w5624932405; }
                else if (number_of_empty_registers == 134) { hll_result = 36w5560588025; }
                else if (number_of_empty_registers == 135) { hll_result = 36w5496722046; }
                else if (number_of_empty_registers == 136) { hll_result = 36w5433327407; }
                else if (number_of_empty_registers == 137) { hll_result = 36w5370397202; }
                else if (number_of_empty_registers == 138) { hll_result = 36w5307924675; }
                else if (number_of_empty_registers == 139) { hll_result = 36w5245903217; }
                else if (number_of_empty_registers == 140) { hll_result = 36w5184326361; }
                else if (number_of_empty_registers == 141) { hll_result = 36w5123187779; }
                else if (number_of_empty_registers == 142) { hll_result = 36w5062481275; }
                else if (number_of_empty_registers == 143) { hll_result = 36w5002200784; }
                else if (number_of_empty_registers == 144) { hll_result = 36w4942340371; }
                else if (number_of_empty_registers == 145) { hll_result = 36w4882894219; }
                else if (number_of_empty_registers == 146) { hll_result = 36w4823856636; }
                else if (number_of_empty_registers == 147) { hll_result = 36w4765222042; }
                else if (number_of_empty_registers == 148) { hll_result = 36w4706984975; }
                else if (number_of_empty_registers == 149) { hll_result = 36w4649140079; }
                else if (number_of_empty_registers == 150) { hll_result = 36w4591682108; }
                else if (number_of_empty_registers == 151) { hll_result = 36w4534605921; }
                else if (number_of_empty_registers == 152) { hll_result = 36w4477906477; }
                else if (number_of_empty_registers == 153) { hll_result = 36w4421578835; }
                else if (number_of_empty_registers == 154) { hll_result = 36w4365618151; }
                else if (number_of_empty_registers == 155) { hll_result = 36w4310019675; }
                else if (number_of_empty_registers == 156) { hll_result = 36w4254778747; }
                else if (number_of_empty_registers == 157) { hll_result = 36w4199890800; }
                else if (number_of_empty_registers == 158) { hll_result = 36w4145351349; }
                else if (number_of_empty_registers == 159) { hll_result = 36w4091155998; }
                else if (number_of_empty_registers == 160) { hll_result = 36w4037300433; }
                else if (number_of_empty_registers == 161) { hll_result = 36w3983780418; }
                else if (number_of_empty_registers == 162) { hll_result = 36w3930591798; }
                else if (number_of_empty_registers == 163) { hll_result = 36w3877730496; }
                else if (number_of_empty_registers == 164) { hll_result = 36w3825192506; }
                else if (number_of_empty_registers == 165) { hll_result = 36w3772973897; }
                else if (number_of_empty_registers == 166) { hll_result = 36w3721070812; }
                else if (number_of_empty_registers == 167) { hll_result = 36w3669479458; }
                else if (number_of_empty_registers == 168) { hll_result = 36w3618196114; }
                else if (number_of_empty_registers == 169) { hll_result = 36w3567217124; }
                else if (number_of_empty_registers == 170) { hll_result = 36w3516538897; }
                else if (number_of_empty_registers == 171) { hll_result = 36w3466157904; }
                else if (number_of_empty_registers == 172) { hll_result = 36w3416070680; }
                else if (number_of_empty_registers == 173) { hll_result = 36w3366273818; }
                else if (number_of_empty_registers == 174) { hll_result = 36w3316763972; }
                else if (number_of_empty_registers == 175) { hll_result = 36w3267537851; }
                else if (number_of_empty_registers == 176) { hll_result = 36w3218592222; }
                else if (number_of_empty_registers == 177) { hll_result = 36w3169923907; }
                else if (number_of_empty_registers == 178) { hll_result = 36w3121529782; }
                else if (number_of_empty_registers == 179) { hll_result = 36w3073406773; }
                else if (number_of_empty_registers == 180) { hll_result = 36w3025551860; }
                else if (number_of_empty_registers == 181) { hll_result = 36w2977962073; }
                else if (number_of_empty_registers == 182) { hll_result = 36w2930634490; }
                else if (number_of_empty_registers == 183) { hll_result = 36w2883566238; }
                else if (number_of_empty_registers == 184) { hll_result = 36w2836754489; }
                else if (number_of_empty_registers == 185) { hll_result = 36w2790196464; }
                else if (number_of_empty_registers == 186) { hll_result = 36w2743889427; }
                else if (number_of_empty_registers == 187) { hll_result = 36w2697830686; }
                else if (number_of_empty_registers == 188) { hll_result = 36w2652017593; }
                else if (number_of_empty_registers == 189) { hll_result = 36w2606447541; }
                else if (number_of_empty_registers == 190) { hll_result = 36w2561117966; }
                else if (number_of_empty_registers == 191) { hll_result = 36w2516026342; }
                else if (number_of_empty_registers == 192) { hll_result = 36w2471170185; }
                else if (number_of_empty_registers == 193) { hll_result = 36w2426547048; }
                else if (number_of_empty_registers == 194) { hll_result = 36w2382154522; }
                else if (number_of_empty_registers == 195) { hll_result = 36w2337990237; }
                else if (number_of_empty_registers == 196) { hll_result = 36w2294051857; }
                else if (number_of_empty_registers == 197) { hll_result = 36w2250337083; }
                else if (number_of_empty_registers == 198) { hll_result = 36w2206843650; }
                else if (number_of_empty_registers == 199) { hll_result = 36w2163569329; }
                else if (number_of_empty_registers == 200) { hll_result = 36w2120511922; }
                else if (number_of_empty_registers == 201) { hll_result = 36w2077669267; }
                else if (number_of_empty_registers == 202) { hll_result = 36w2035039231; }
                else if (number_of_empty_registers == 203) { hll_result = 36w1992619715; }
                else if (number_of_empty_registers == 204) { hll_result = 36w1950408649; }
                else if (number_of_empty_registers == 205) { hll_result = 36w1908403995; }
                else if (number_of_empty_registers == 206) { hll_result = 36w1866603744; }
                else if (number_of_empty_registers == 207) { hll_result = 36w1825005917; }
                else if (number_of_empty_registers == 208) { hll_result = 36w1783608562; }
                else if (number_of_empty_registers == 209) { hll_result = 36w1742409756; }
                else if (number_of_empty_registers == 210) { hll_result = 36w1701407603; }
                else if (number_of_empty_registers == 211) { hll_result = 36w1660600236; }
                else if (number_of_empty_registers == 212) { hll_result = 36w1619985813; }
                else if (number_of_empty_registers == 213) { hll_result = 36w1579562517; }
                else if (number_of_empty_registers == 214) { hll_result = 36w1539328557; }
                else if (number_of_empty_registers == 215) { hll_result = 36w1499282170; }
                else if (number_of_empty_registers == 216) { hll_result = 36w1459421613; }
                else if (number_of_empty_registers == 217) { hll_result = 36w1419745170; }
                else if (number_of_empty_registers == 218) { hll_result = 36w1380251148; }
                else if (number_of_empty_registers == 219) { hll_result = 36w1340937878; }
                else if (number_of_empty_registers == 220) { hll_result = 36w1301803712; }
                else if (number_of_empty_registers == 221) { hll_result = 36w1262847026; }
                else if (number_of_empty_registers == 222) { hll_result = 36w1224066217; }
                else if (number_of_empty_registers == 223) { hll_result = 36w1185459704; }
                else if (number_of_empty_registers == 224) { hll_result = 36w1147025928; }
                else if (number_of_empty_registers == 225) { hll_result = 36w1108763350; }
                else if (number_of_empty_registers == 226) { hll_result = 36w1070670451; }
                else if (number_of_empty_registers == 227) { hll_result = 36w1032745734; }
                else if (number_of_empty_registers == 228) { hll_result = 36w994987719; }
                else if (number_of_empty_registers == 229) { hll_result = 36w957394947; }
                else if (number_of_empty_registers == 230) { hll_result = 36w919965979; }
                else if (number_of_empty_registers == 231) { hll_result = 36w882699393; }
                else if (number_of_empty_registers == 232) { hll_result = 36w845593786; }
                else if (number_of_empty_registers == 233) { hll_result = 36w808647774; }
                else if (number_of_empty_registers == 234) { hll_result = 36w771859989; }
                else if (number_of_empty_registers == 235) { hll_result = 36w735229083; }
                else if (number_of_empty_registers == 236) { hll_result = 36w698753722; }
                else if (number_of_empty_registers == 237) { hll_result = 36w662432591; }
                else if (number_of_empty_registers == 238) { hll_result = 36w626264392; }
                else if (number_of_empty_registers == 239) { hll_result = 36w590247842; }
                else if (number_of_empty_registers == 240) { hll_result = 36w554381675; }
                else if (number_of_empty_registers == 241) { hll_result = 36w518664640; }
                else if (number_of_empty_registers == 242) { hll_result = 36w483095501; }
                else if (number_of_empty_registers == 243) { hll_result = 36w447673040; }
                else if (number_of_empty_registers == 244) { hll_result = 36w412396052; }
                else if (number_of_empty_registers == 245) { hll_result = 36w377263346; }
                else if (number_of_empty_registers == 246) { hll_result = 36w342273748; }
                else if (number_of_empty_registers == 247) { hll_result = 36w307426095; }
                else if (number_of_empty_registers == 248) { hll_result = 36w272719241; }
                else if (number_of_empty_registers == 249) { hll_result = 36w238152054; }
                else if (number_of_empty_registers == 250) { hll_result = 36w203723412; }
                else if (number_of_empty_registers == 251) { hll_result = 36w169432210; }
                else if (number_of_empty_registers == 252) { hll_result = 36w135277356; }
                else if (number_of_empty_registers == 253) { hll_result = 36w101257768; }
                else if (number_of_empty_registers == 254) { hll_result = 36w67372381; }
                else if (number_of_empty_registers == 255) { hll_result = 36w33620139; }
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
