#!/bin/bash
# Author : Vamshidhar Reddy Dudyala
# Email : vamshi.dudyala@gmail.com
sed -i -e '1,4d' sys_log.json
sed -i -e 's/$/,/' sys_log.json
sed -i '$ s/.$//' sys_log.json
sed  -i '1i [' sys_log.json
echo "]" >> sys_log.json