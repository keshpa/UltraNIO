#!/usr/bin/bash

tc qdisc add dev $6 clsact 2>&1 | grep -v "Exclusivity flag on" ;
tc qdisc add dev $6 ingress 2>&1 | grep -v "Exclusivity flag on";

tc filter delete dev $6 ingress 

rm $6_$4_host_ingress.o

$prefix ./qos_qdisc_create.sh $6

$prefix ./disable_offloads.sh $6

# compile the kernel ebpf program
clang -O2 -g -Wall -mcpu=v3 -fstack-usage -I /usr/include/x86_64-linux-gnu 							\
				-DLOCAL_TIP_OFFSET_MASK=$1									\
				-DLOCAL_TIP_MASK=$2										\
				-DLOCAL_UNDERLAY_GW_IP=$5									\
				-DLOCAL_HOST_ETH_INDEX=$3									\
				-DLOCAL_HOST_ETH_MAC=$4		 								\
				-DDEBUG=0											\
				-DEGRESS=0											\
				-DHOST=1											\
				-DENCAP_VNI_ID=$7										\
				-DLOCAL_HOST_ETH_IP=$8										\
				-DLOCAL_HOST_ETH_L2_CIDR=$9									\
				-DLOCAL_UVM_DEFAULT_ROUTER_MAC=0xaddeaddeadde							\
				-Wno-unused-function										\
				-Wno-implicit-function-declaration								\
				-Wno-gcc-compat											\
				-target bpf -c host_ingress.c -o $6_$4_host_ingress.o	&&

# load the kernel ebpf program
tc filter add dev $6 ingress bpf direct-action obj $6_$4_host_ingress.o section tc/request_host_ingress &&
echo -n $6-$4 "  " ; tc filter show dev $6 ingress

./rc_qos.sh $6 0 $2 1 $7 $1

echo "done"
