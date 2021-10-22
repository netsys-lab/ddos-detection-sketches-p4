#!/bin/bash

IMPLEMENTATION_DIR=/home/p4/ddos/implementation
LOGS_DIR=logs/hyperloglog+countmin-experiment
PCAP_DIR=pcap/hyperloglog+countmin-experiment
CARDINALITY=40000
PCAP_LOGS=false

# Kill leftover screen sessions
if screen -list | grep -q 'p4run'; then
    screen -X -S p4run quit
    sleep 2
fi
if screen -list | grep -q 'rollover'; then
    screen -X -S rollover quit
    sleep 2
fi
if screen -list | grep -q 'estimates'; then
    screen -X -S estimates quit
    sleep 2
fi

# Delete old pcap logs
if $PCAP_LOGS; then
    rm -r pcap/*
fi

# Make sure log directories exist
if [ ! -d "$LOGS_DIR" ]; then
    mkdir $LOGS_DIR
fi
if [ ! -d "$LOGS_DIR/old" ]; then
    mkdir $LOGS_DIR/old
fi

# Move old logs
if [ ! -z "$(stat $IMPLEMENTATION_DIR/$LOGS_DIR/*.txt 2>/dev/null)" ]; then
    if [ ! -z "$(stat $IMPLEMENTATION_DIR/$LOGS_DIR/old/*.txt 2>/dev/null)" ]; then
        rm $IMPLEMENTATION_DIR/$LOGS_DIR/old/*
    fi
    mv $IMPLEMENTATION_DIR/$LOGS_DIR/*.txt $LOGS_DIR/old
fi

# Start p4run
echo 'Starting p4run'
screen -d -m -S p4run
screen -S p4run -X register c $'sudo p4run\n'
screen -S p4run -X paste c
sleep 10

# Reset log files
echo -n '' > $LOGS_DIR/hyperloglog-results.txt
echo -n '' > $LOGS_DIR/countmin-results.txt
echo -n '' > $LOGS_DIR/hyperloglog-inactive-results.txt
echo -n '' > $LOGS_DIR/countmin-inactive-results.txt
echo -n '' > $LOGS_DIR/rollover.txt

echo "Starting experiment with c = $CARDINALITY"

# Set custom CRCs
python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --option "set_hashes"

# Enable sketch rollover
echo 'Enabling sketch rollover'
screen -d -m -S rollover
screen -S rollover -X register c $'scripts/sketch-rollover.sh\n'
screen -S rollover -X paste c

# Get estimates from switch continuously and write to log files
echo 'Start loop getting estimates from switch'
screen -d -m -S estimates
screen -S estimates -X register c $'scripts/get_estimates.sh\n'
screen -S estimates -X paste c

# Send packets
echo "Starting to send packets"
mx h1 python $IMPLEMENTATION_DIR/scripts/send.py --n-src $CARDINALITY
echo "Done sending packets"

# Get estimates from switch and write to log files
screen -X -S estimates quit
echo 'Stored results'

# Move pcap logs to pcap log directory
if $PCAP_LOGS; then
    echo "Moving pcap files"
    mkdir -p $PCAP_DIR
    mv pcap/*.pcap $PCAP_DIR
fi

# Kill screens
echo 'Killing p4run'
screen -X -S p4run quit
echo 'Stopping sketch rollover'
screen -X -S rollover quit
