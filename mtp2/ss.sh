#!/bin/bash
ss -t -u -x -p -a | grep --color -E 'users:\(\(\"(nginx|postgres|gunicorn)\"'