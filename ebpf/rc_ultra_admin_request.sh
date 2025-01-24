#!/usr/bin/bash

tc qdisc add dev $1 clsact 2>&1 | grep -v "Exclusivity flag on" ;
tc qdisc add dev $1 ingress 2>&1 | grep -v "Exclusivity flag on";

tc filter delete dev $1 egress 
rm $2_ultra_admin.o
# compile the kernel ebpf program
clang -O2 -g -Wall -mcpu=v3 -fstack-usage -I /usr/include/x86_64-linux-gnu 							\
				-Wno-unused-function										\
				-Wno-implicit-function-declaration								\
				-Wno-gcc-compat											\
				-DDEBUG=0											\
				-DLOCAL_TIP_OFFSET_MASK=$3									\
				-DLOCAL_TIP_MASK=$4										\
				-DENCAP_VNI_ID=$5										\
				-target bpf -c ultra_admin.c -o $2_ultra_admin.o	&&

# load the kernel ebpf program
tc filter add dev $1 egress bpf direct-action obj $2_ultra_admin.o section tc/ultra_admin_egress &&
echo -n ultra_admin-$2 "  " ; tc filter show dev $1 egress
