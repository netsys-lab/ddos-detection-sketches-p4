#!/bin/bash

IMPLEMENTATION_DIR=/home/p4/ddos/implementation
LOGS_DIR=logs/hyperloglog+countmin-experiment
NUM_HYPERLOGLOG_REGISTERS=65536
NUM_COUNTMIN_REGISTERS=28

# Note: one loop takes approx. 10 seconds
while true; do
    # Get active sketch estimates
    echo -n "$(date +%s)," >> $LOGS_DIR/hyperloglog-results.txt
    python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --hyperloglog-registers $NUM_HYPERLOGLOG_REGISTERS --option decode_hyperloglog >> $LOGS_DIR/hyperloglog-results.txt
    echo -n "$(date +%s)," >> $LOGS_DIR/countmin-results.txt
    python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --countmin-registers $NUM_COUNTMIN_REGISTERS --countmin-flow "10.0.1.1" --option decode_countmin >> $LOGS_DIR/countmin-results.txt

    # Get inactive sketch estimates
    echo -n "$(date +%s)," >> $LOGS_DIR/hyperloglog-inactive-results.txt
    python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --hyperloglog-registers $NUM_HYPERLOGLOG_REGISTERS --get-inactive 1 --option decode_hyperloglog >> $LOGS_DIR/hyperloglog-inactive-results.txt
    echo -n "$(date +%s)," >> $LOGS_DIR/countmin-inactive-results.txt
    python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --countmin-registers $NUM_COUNTMIN_REGISTERS --countmin-flow "10.0.1.1" --get-inactive 1 --option decode_countmin >> $LOGS_DIR/countmin-inactive-results.txt

    # python $IMPLEMENTATION_DIR/scripts/read_counters.py >> $LOGS_DIR/real.txt
done
