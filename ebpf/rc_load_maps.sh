#!/usr/bin/bash
#
ip tuntap add mode tap ultra_temporary;

tc qdisc del dev ultra_temporary clsact
tc qdisc del dev ultra_temporary ingress

tc qdisc add dev ultra_temporary clsact
tc qdisc add dev ultra_temporary ingress
tc filter delete dev ultra_temporary ingress
tc filter delete dev ultra_temporary egress

# compile the kernel ebpf program
clang -O2 -g -Wall -mcpu=v3 -fstack-usage -I /usr/include/x86_64-linux-gnu                                                      \
				-DLOCAL_TIP_OFFSET_MASK=0 -DLOCAL_TIP_MASK=0							\
				-DLOCAL_UNDERLAY_GW_IP=0x01020304 								\
				-DLOCAL_HOST_ETH_INDEX=0									\
				-DLOCAL_HOST_ETH_MAC=0		 								\
				-DLOCAL_HOST_ETH_IP=0										\
				-DLOCAL_UVM_DEFAULT_ROUTER_MAC=0								\
				-DLOCAL_HOST_ETH_L2_CIDR=0									\
				-DENCAP_VNI_ID=0										\
				-DDEBUG=1											\
				-DEGRESS=0											\
				-DHOST=1											\
				-Wno-unused-function										\
				-Wno-implicit-function-declaration								\
				-Wno-gcc-compat											\
				-target bpf -c host_ingress.c -o load_maps.o	&&

# load the kernel ebpf program just to load all maps and then remove the ebpf program
tc filter add dev ultra_temporary ingress bpf direct-action obj load_maps.o section tc/load_all_maps 
tc filter show dev ultra_temporary ingress
tc filter show dev ultra_temporary egress
tc filter delete dev ultra_temporary ingress 


ip tuntap del mode tap ultra_temporary
