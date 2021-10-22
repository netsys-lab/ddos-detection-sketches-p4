/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers-reference.p4"
#include "include/parsers.p4"

/* CONSTANTS */

/* Keep exact packet counter for comparison (for evaluation or debugging) */

#define KEEP_EXACT_PACKET_COUNT 0

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
