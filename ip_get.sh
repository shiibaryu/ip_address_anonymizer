#!bin/sh
HOST=`hostname`

mkdir $HOST
ip route > $HOST/ip_route.txt
ip vrf > $HOST/ip_vrf.txt
ip -6 route > $HOST/ip_6_route.txt
ip -j addr > $HOST/ip_j_addr.json
