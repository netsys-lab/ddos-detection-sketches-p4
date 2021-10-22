#!/bin/bash

# NOTE:
# To monitor mininet or the controller while they are running, attach to their screen sessions:
# $ screen -r p4run
# $ screen -r p4controller

IMPLEMENTATION_DIR=/home/p4/ddos-hyperloglog/implementation

SAMPLE_SIZE=10 # Number of runs per cardinality
MIN_CARDINALITY=1500 # Number of source IPs
MAX_CARDINALITY=1500
NUMBER_OF_PACKETS_PER_SOURCE=100

PCAP_LOGS=true # .pcap logs must be enabled by setting "pcap_dump": true in p4app.json

WAIT_FOR_SWITCH_START=10 # Seconds to wait for switch to start (incl. program compilation)
# Recommended values:
# For m = 16: WAIT_FOR_SWITCH_START=15
# For m = 256: WAIT_FOR_SWITCH_START=25
# Increase if this error message is shown:
# "Could not connect to thrift client on port 9090"
# "Make sure the switch is running and that you have the right port"
WAIT_FOR_SWITCH_FINISH=10 # Seconds to wait for switch to finish forwarding packets before killing p4run

if screen -list | grep -q 'p4run'; then
    echo "Killing leftover p4run"
    screen -X -S p4run quit
    sleep 2
fi
if screen -list | grep -q 'p4controller'; then
    echo "Killing leftover p4controller"
    screen -X -S p4controller quit
    sleep 2
fi

# Move old logs
mkdir -p logs/old
if [ ! -z "$(stat $IMPLEMENTATION_DIR/logs/*.txt 2>/dev/null)" ]; then
    if [ ! -z "$(stat $IMPLEMENTATION_DIR/logs/old/*.txt 2>/dev/null)" ]; then
        rm $IMPLEMENTATION_DIR/logs/old/*
    fi
    mv $IMPLEMENTATION_DIR/logs/*.txt logs/old
fi

echo -n "Starting p4run"
screen -d -m -S p4run
screen -S p4run -X register c $'sudo p4run\n'
screen -S p4run -X paste c

for ((i=0; i<WAIT_FOR_SWITCH_START; i++))
do
    echo -n '.'
    sleep 1
done
echo ''

echo "Starting controller"
screen -d -m -S p4controller
screen -S p4controller -X register c $'sudo python hyperloglog+countmin-sketch-in-data-plane-controller.py\n'
screen -S p4controller -X paste c

for ((c=MIN_CARDINALITY; c<=MAX_CARDINALITY; c=c*10))
do
    echo -n '' > logs/$c.txt

    echo ""
    echo "Starting $SAMPLE_SIZE experiment(s) for c = $c"

    for ((i=0; i<SAMPLE_SIZE; i++))
    do
        if [ $i -gt 0 ]; then
            screen -S p4run -X register c $'p4switch_reboot s1\n'
            screen -S p4run -X paste c
            echo -n "Rebooting switch"
            for ((t=0; t<WAIT_FOR_SWITCH_START; t++))
            do
                echo -n '.'
                sleep 1
            done
            echo ''
            echo "Restarting controller"
            screen -S p4controller -X stuff ^C
            screen -S p4controller -X register c $'sudo python hyperloglog+countmin-sketch-in-data-plane-controller.py\n'
            screen -S p4controller -X paste c
        fi

        python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --option "set_hashes"

        echo "Starting to send packets ($((i+1))/$SAMPLE_SIZE)"
        mx h1 python $IMPLEMENTATION_DIR/scripts/send.py --n-src $c --n-pkt $NUMBER_OF_PACKETS_PER_SOURCE
        echo "Done sending packets ($((i+1))/$SAMPLE_SIZE)"

        if [ $WAIT_FOR_SWITCH_FINISH -gt 0 ]; then
            echo -n "Waiting for switch to finish forwarding packets"
            for ((t=0; t<WAIT_FOR_SWITCH_FINISH; t++))
            do
                echo -n '.'
                sleep 1
            done
            echo ''
        fi

        python $IMPLEMENTATION_DIR/hyperloglog+countmin-sketch-controller.py --option "read_estimates" >> logs/$c.txt
        echo "Stored results ($((i+1))/$SAMPLE_SIZE)"

        if $PCAP_LOGS; then
            echo "Moving pcap files ($((i+1))/$SAMPLE_SIZE)"
            mkdir -p pcap/$c/$((i+1))
            mv pcap/*.pcap pcap/$c/$((i+1))
        fi
    done
done

echo ""
echo "Killing p4run"
screen -X -S p4run quit
echo "Killing controller"
screen -X -S p4controller quit
