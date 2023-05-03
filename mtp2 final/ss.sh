#!/bin/bash
# Author : Vamshidhar Reddy Dudyala
# Email : vamshi.dudyala@gmail.com
exp=$(tr ',' '|' <<< $1)
exp="users:\(\(\"($exp)\""
# date +%s%N | cut -b1-13
# ./ss_util.sh $exp
# date +%s%N | cut -b1-13
mkdir ss_out
file="ss_out/"
i=1
while : 
do
    outfile=$(echo "${file}${i}")
    end=$((SECONDS+20))
    date +%s%N >> timestamps
    while [ $SECONDS -lt $end ]; 
    do
        ./ss_util.sh $exp >> "$outfile"
    done
    i=$(( $i + 1 ))
done