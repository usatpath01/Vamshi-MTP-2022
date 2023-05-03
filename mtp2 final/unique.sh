#!/bin/bash
# Author : Vamshidhar Reddy Dudyala
# Email : vamshi.dudyala@gmail.com
cd ss_out
for FILE in *; do awk '{$1=$1};!seen[$0]++' $FILE > tmp && mv tmp $FILE; done