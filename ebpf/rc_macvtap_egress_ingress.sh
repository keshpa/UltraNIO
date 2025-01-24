#!/usr/bin/bash

prefix=""
$prefix tc qdisc add dev $1 clsact 2>&1 | grep -v "Exclusivity flag on" ;
$prefix tc qdisc add dev $1 ingress 2>&1 | grep -v "Exclusivity flag on";

$prefix tc filter delete dev $1;
$prefix tc filter delete dev $1 egress;
$prefix tc filter delete dev $1 ingress;

rm $1_request_egress.o;
rm $1_request_ingress.o;

$prefix ./qos_qdisc_create.sh $1

$prefix ./disable_offloads.sh $1

clang -O2 -g -Wall -Wno-gcc-compat -mcpu=v3 -fstack-usage		 									\
			-I /usr/include/x86_64-linux-gnu                                                      					\
			-DLOCAL_UVM_IP=$2 			-DLOCAL_UVM_TIP=$3 			-DLOCAL_UVM_NONAT_HOST_MAC=${11}	\
                        -DLOCAL_UVM_SUB_MASK=$8			-DLOCAL_UVM_SUB_TIP=$7	 		-DLOCAL_HOST_ETH_MAC=${10}	 	\
                        -DLOCAL_HOST_ETH_IFINDEX=$9 		-DLOCAL_UVM_SUB_GW_IP=$6		-DLOCAL_UVM_VPCID=${16}			\
			-DLOCAL_UVM_VPC_MASK=${12} 		-DLOCAL_UVM_SUB_GW_MAC=0xaddeaddeadde	-DLOCAL_UNDERLAY_GW_IP=${17}		\
			-DDEBUG=0				-DLOCAL_UVM_MAC=$4			-DLOCAL_HOST_ETH_IP=${18}		\
			-DLOCAL_UVM_IS_ROUTER=${15}		-DEGRESS=1				-DLOCAL_TIP_OFFSET_MASK=${13}		\
			-DLOCAL_TIP_MASK=${14}			-DSEND_PROXY_ARP_RESPONSE=1		-DLOCAL_UVM_PRIMARY_IFINDEX=$5		\
			-DHOST=0				-DLOCAL_UVM_CHECK_SRC_DEST=1		-DENABLE_ROUTER_LOOPBACK=1		\
			-DLOCAL_UVM_LB_MAC=0xeddeeddeedde	-DMEASURE_MSEG_TIME=1			-DENCAP_VNI_ID=${19}			\
			-DLOCAL_HOST_ETH_L2_CIDR=${20}		-DLOCAL_VETH_PAIR=${21}			-DLOOPBACK_EGRESS_IFINDEX=${22}		\
			-Wno-unused-function													\
			-Wno-implicit-function-declaration											\
			-Wno-gcc-compat														\
			-Wno-address-of-packed-member												\
			-target bpf -c egress_ingress_mvtap.c -o $1_request_egress.o &&

clang -O2 -g -Wall -Wno-gcc-compat -mcpu=v3 -fstack-usage		 									\
			-I /usr/include/x86_64-linux-gnu                                                      					\
			-DLOCAL_UVM_IP=$2 			-DLOCAL_UVM_TIP=$3 			-DLOCAL_UVM_NONAT_HOST_MAC=${11}	\
                        -DLOCAL_UVM_SUB_MASK=$8			-DLOCAL_UVM_SUB_TIP=$7	 		-DLOCAL_HOST_ETH_MAC=${10}		\
                        -DLOCAL_HOST_ETH_IFINDEX=$9 		-DLOCAL_UVM_SUB_GW_IP=$6		-DLOCAL_UVM_VPCID=${16}			\
			-DLOCAL_UVM_VPC_MASK=${12} 		-DLOCAL_UVM_SUB_GW_MAC=0xaddeaddeadde 	-DLOCAL_UNDERLAY_GW_IP=${17}		\
			-DDEBUG=0				-DLOCAL_UVM_MAC=$4			-DLOCAL_HOST_ETH_IP=${18}		\
			-DLOCAL_UVM_IS_ROUTER=${15}		-DEGRESS=0				-DLOCAL_TIP_OFFSET_MASK=${13}		\
			-DLOCAL_TIP_MASK=${14}			-DSEND_PROXY_ARP_RESPONSE=1		-DLOCAL_UVM_PRIMARY_IFINDEX=$5		\
			-DHOST=0				-DLOCAL_UVM_CHECK_SRC_DEST=1		-DENABLE_ROUTER_LOOPBACK=1		\
			-DLOCAL_UVM_LB_MAC=0xeddeeddeedde	-DMEASURE_MSEG_TIME=1 			-DENCAP_VNI_ID=${19}			\
			-DLOCAL_HOST_ETH_L2_CIDR=${20}		-DLOCAL_VETH_PAIR=${21}			-DLOOPBACK_EGRESS_IFINDEX=${22}		\
			-Wno-unused-function													\
			-Wno-implicit-function-declaration											\
			-Wno-gcc-compat														\
			-Wno-address-of-packed-member												\
			-target bpf -c egress_ingress_mvtap.c -o $1_request_ingress.o &&


echo "attaching egress to tc"; 
$prefix tc filter add dev $1 egress bpf direct-action obj $1_request_egress.o section tc/macvtap_egress classid 1: &&
$prefix tc exec bpf graft m:globals/egress_prog_array_init key 0 obj $1_request_egress.o sec tc/tail_macvtap_eprocess
$prefix tc exec bpf graft m:globals/egress_prog_array_init key 1 obj $1_request_egress.o sec tc/tail_macvtap_esend
echo -n $1 "  " ; $prefix tc filter show dev $1 egress && 

echo "attaching ingress to tc"; 
$prefix tc filter add dev $1 ingress bpf direct-action obj $1_request_ingress.o section tc/macvtap_ingress classid 1: &&
$prefix tc exec bpf graft m:globals/ingress_prog_array_init key 0 obj $1_request_ingress.o sec tc/tail_macvtap_iprocess
$prefix tc exec bpf graft m:globals/ingress_prog_array_init key 1 obj $1_request_ingress.o sec tc/tail_macvtap_isend
echo -n $1 "  " ; $prefix tc filter show dev $1 ingress && 

./rc_qos.sh $1 1 ${14} 0 ${19} ${13}

echo "done";
