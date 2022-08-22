HOST=`hostname`
ip route > ip_route.txt
g++ ip_route.cc -o ipr
./ipr ip_route.txt > $HOST/ano_ip_route.txt
