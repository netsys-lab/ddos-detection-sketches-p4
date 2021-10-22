#!/bin/bash

IMPLEMENTATION_DIR=/home/p4/ddos/implementation
LOGS_DIR=logs/hyperloglog+countmin-experiment

while true; do
    sleep 10
    python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --option switch_active_sketches >> $LOGS_DIR/rollover.txt
done
