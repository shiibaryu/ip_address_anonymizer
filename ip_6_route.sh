HOST=`hostname`
ip -6 route > ip_6_route.txt
g++ ip_6_route.cc -o ip6r
./ip6r ip_6_route.txt > $HOST/ano_ip_6_route.txt
