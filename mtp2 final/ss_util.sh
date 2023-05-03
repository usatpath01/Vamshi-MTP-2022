#!/bin/bash
# Author : Vamshidhar Reddy Dudyala
# Email : vamshi.dudyala@gmail.com
ss -t -u -x -p -a | grep --color -E "$1"