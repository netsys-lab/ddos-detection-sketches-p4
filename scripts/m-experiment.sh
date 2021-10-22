#!/bin/bash

IMPLEMENTATION_DIR=/home/p4/ddos/implementation
SAMPLE_SIZE=20
MIN_CARDINALITY=10
MAX_CARDINALITY=1000000
PCAP_LOGS=false
NUM_REGISTERS=65536

if screen -list | grep -q 'p4run'; then
    echo 'Killing leftover p4run'
    screen -X -S p4run quit
    sleep 2
fi

if $PCAP_LOGS; then
    rm -r pcap/*
fi


if [ ! -z "$(stat $IMPLEMENTATION_DIR/logs/*.txt 2>/dev/null)" ]; then
    if [ ! -z "$(stat $IMPLEMENTATION_DIR/logs/old/*.txt 2>/dev/null)" ]; then
        rm $IMPLEMENTATION_DIR/logs/old/*
    fi
    mv $IMPLEMENTATION_DIR/logs/*.txt logs/old
fi

echo 'Starting p4run'
screen -d -m -S p4run
screen -S p4run -X register c $'sudo p4run\n'
screen -S p4run -X paste c
sleep 10

for ((c=MIN_CARDINALITY; c<=MAX_CARDINALITY; c=c*10))
do
    echo -n '' > logs/results-$c.txt
    echo -n '' > logs/real-$c.txt

    echo "Starting $SAMPLE_SIZE experiments for c = $c"

    for ((i=0; i<SAMPLE_SIZE; i++))
    do
        screen -S p4run -X register c $'p4switch_reboot s1\n'
        screen -S p4run -X paste c
        sleep 3

        python $IMPLEMENTATION_DIR/hyperloglog-sketch-controller.py --option "set_hashes"

        echo "Starting to send packets ($((i+1))/$SAMPLE_SIZE)"
        mx h1 python $IMPLEMENTATION_DIR/scripts/send.py --n-src $c
        echo "Done sending packets ($((i+1))/$SAMPLE_SIZE)"

        python $IMPLEMENTATION_DIR/hyperloglog-sketch-controller.py --m $NUM_REGISTERS --option decode >> logs/results-$c.txt
        python $IMPLEMENTATION_DIR/scripts/read_counters.py >> logs/real-$c.txt
        echo "Stored results ($((i+1))/$SAMPLE_SIZE)"

        if $PCAP_LOGS; then
            echo "Moving pcap files ($((i+1))/$SAMPLE_SIZE)"
            mkdir -p pcap/$c/$i
            mv pcap/*.pcap pcap/$c/$i
        fi
    done
done

echo 'Killing p4run'
screen -X -S p4run quit
