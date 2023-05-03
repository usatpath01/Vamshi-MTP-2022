#!/bin/bash
# Author : Vamshidhar Reddy Dudyala
# Email : vamshi.dudyala@gmail.com
docker run \
    --name tracee --rm -it \
    --pid=host --cgroupns=host --privileged \
    -v /etc/os-release:/etc/os-release-host:ro \
    -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
    aquasec/tracee:0.10.0 \
    trace \
    --output json \
    --trace comm=$@ \
    --trace event=clone,openat,read,write,close,rename,security_socket_accept,socket_accept,socket,security_socket_create,security_socket_connect,connect,accept,accept4,net_packet_tcp,net_packet_ipv4,net_packet_udp,sendto,recvfrom,recvmsg,sendmsg,listen,security_socket_listen,bind,security_socket_bind,socketpair,chdir \
    --trace net=lo > sys_log.json
    # --trace event=clone,openat,read,write,close,rename,security_socket_accept,socket_accept,socket,security_socket_create,security_socket_connect,connect,accept,accept4,net_packet_tcp,net_packet_ipv4,net_packet_udp,sendto,recvfrom,recvmsg,sendmsg,listen,security_socket_listen,bind,security_socket_bind,socketpair,chdir \
    # --trace event=read,write,bind,connect,accept,accept4,clone,close,creat,dup,dup2,dup3,execve,exit,exit_group,fork,kill,open,openat,rename,renameat,unlink,unlinkat,vfork,pipe \