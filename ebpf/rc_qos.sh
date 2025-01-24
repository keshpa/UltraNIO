#!/usr/bin/bash

clang -O2 -g -Wall -Wno-gcc-compat -mcpu=v3 -fstack-usage		 									\
			-I /usr/include/x86_64-linux-gnu                                                      					\
			-DDEBUG=0														\
			-DHOST=$2														\
			-DLOCAL_TIP_MASK=$3													\
			-DEGRESS=$4														\
			-DENCAP_VNI_ID=$5													\
			-DLOCAL_TIP_OFFSET_MASK=$6												\
			-Wno-unused-function													\
			-Wno-implicit-function-declaration											\
			-Wno-gcc-compat														\
			-Wno-address-of-packed-member												\
			-target bpf -c qos_ebpf.c -o qos_ebpf.o

tc filter add dev $1 parent 1:0 bpf obj qos_ebpf.o section tc/host_egr direct-action classid 1:
